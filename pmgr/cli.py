from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .store import default_vault_path, vault_exists, init_vault, load_vault, save_vault

app = typer.Typer(
    help="A small learning password manager (encrypted vault + CLI).",
    add_completion=False,
)

console = Console()


def resolve_vault_path(vault: Optional[Path]) -> Path:
    return vault if vault is not None else default_vault_path()


def prompt_master(confirm: bool = False) -> str:
    pw = typer.prompt("Master password", hide_input=True)
    if confirm:
        pw2 = typer.prompt("Confirm master password", hide_input=True)
        if pw != pw2:
            raise typer.BadParameter("Passwords do not match.")
    return pw


@app.command()
def init(vault: Optional[Path] = typer.Option(None, "--vault", "-v", help="Path to vault file")):
    """
    Initialize a new encrypted vault.
    """
    vault_path = resolve_vault_path(vault)
    if vault_exists(vault_path):
        raise typer.BadParameter(f"Vault already exists at: {vault_path}")

    master = prompt_master(confirm=True)
    init_vault(vault_path, master)
    console.print(f"[green]Created vault:[/green] {vault_path}")


@app.command()
def add(
    name: str = typer.Argument(..., help="Entry name (e.g., 'gmail', 'github')"),
    username: str = typer.Option("", "--username", "-u", help="Username/email for the entry"),
    vault: Optional[Path] = typer.Option(None, "--vault", "-v", help="Path to vault file"),
):
    """
    Add or update a secret.
    """
    vault_path = resolve_vault_path(vault)
    if not vault_exists(vault_path):
        raise typer.BadParameter(f"Vault not found at: {vault_path}. Run: pmgr init")

    master = prompt_master(confirm=False)
    header, data = load_vault(vault_path, master)

    secret = typer.prompt("Password", hide_input=True)
    data["items"][name] = {"username": username, "password": secret}

    save_vault(vault_path, header, master, data)
    console.print(f"[green]Saved[/green] entry: [bold]{name}[/bold]")


@app.command()
def get(
    name: str = typer.Argument(..., help="Entry name"),
    show: bool = typer.Option(False, "--show", help="Print the password (unsafe)"),
    vault: Optional[Path] = typer.Option(None, "--vault", "-v", help="Path to vault file"),
):
    """
    Retrieve a secret (masked by default).
    """
    vault_path = resolve_vault_path(vault)
    master = prompt_master(confirm=False)
    _, data = load_vault(vault_path, master)

    item = data["items"].get(name)
    if not item:
        raise typer.BadParameter(f"No entry named '{name}' found.")

    username = item.get("username", "")
    password = item.get("password", "")

    console.print(f"[bold]{name}[/bold]")
    if username:
        console.print(f"  username: {username}")

    if show:
        console.print(f"  password: {password}")
    else:
        console.print(f"  password: {'*' * max(8, len(password))}  (use --show to reveal)")


@app.command("list")
def list_entries(
    vault: Optional[Path] = typer.Option(None, "--vault", "-v", help="Path to vault file"),
):
    """
    List stored entries (no passwords shown).
    """
    vault_path = resolve_vault_path(vault)
    master = prompt_master(confirm=False)
    _, data = load_vault(vault_path, master)

    table = Table(title="Vault entries")
    table.add_column("name", style="bold")
    table.add_column("username")

    for name, item in sorted(data["items"].items()):
        table.add_row(name, item.get("username", ""))

    console.print(table)


@app.command()
def delete(
    name: str = typer.Argument(..., help="Entry name"),
    vault: Optional[Path] = typer.Option(None, "--vault", "-v", help="Path to vault file"),
):
    """
    Delete an entry.
    """
    vault_path = resolve_vault_path(vault)
    master = prompt_master(confirm=False)
    header, data = load_vault(vault_path, master)

    if name not in data["items"]:
        raise typer.BadParameter(f"No entry named '{name}' found.")

    del data["items"][name]
    save_vault(vault_path, header, master, data)
    console.print(f"[yellow]Deleted[/yellow] entry: [bold]{name}[/bold]")
