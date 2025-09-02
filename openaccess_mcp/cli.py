"""CLI for OpenAccess MCP."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .server import OpenAccessMCPServer
from .audit import get_audit_logger, create_audit_signer
from .secrets import initialize_secret_store

app = typer.Typer(help="OpenAccess MCP - Secure remote access server")
console = Console()


@app.command()
def start(
    profiles: Path = typer.Option(
        "./profiles",
        "--profiles",
        "-p",
        help="Directory containing profile JSON files"
    ),
    vault_addr: Optional[str] = typer.Option(
        None,
        "--vault-addr",
        help="HashiCorp Vault address"
    ),
    vault_token: Optional[str] = typer.Option(
        None,
        "--vault-token",
        help="HashiCorp Vault token"
    ),
    secrets_dir: Optional[Path] = typer.Option(
        None,
        "--secrets-dir",
        help="Directory for file-based secrets"
    ),
    audit_log: Optional[Path] = typer.Option(
        None,
        "--audit-log",
        help="Audit log file path"
    ),
    audit_key: Optional[Path] = typer.Option(
        None,
        "--audit-key",
        help="Audit signing key path"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose logging"
    )
):
    """Start the OpenAccess MCP server."""
    try:
        # Validate profiles directory
        if not profiles.exists():
            console.print(f"[red]Error: Profiles directory not found: {profiles}[/red]")
            sys.exit(1)
        
        # Initialize secret store
        if vault_addr and vault_token:
            initialize_secret_store(
                vault_addr=vault_addr,
                vault_token=vault_token,
                secrets_dir=secrets_dir
            )
            console.print(f"[green]✓[/green] Vault integration enabled")
        elif secrets_dir:
            initialize_secret_store(secrets_dir=secrets_dir)
            console.print(f"[green]✓[/green] File-based secrets enabled")
        else:
            console.print("[yellow]⚠[/yellow] No secret store configured, using defaults")
        
        # Initialize audit system
        if audit_key:
            signer = create_audit_signer(audit_key)
            console.print(f"[green]✓[/green] Audit signing enabled with key: {audit_key}")
        else:
            signer = create_audit_signer()
            console.print(f"[green]✓[/green] Audit signing enabled with generated key")
        
        if audit_log:
            audit_logger = get_audit_logger(audit_log)
            console.print(f"[green]✓[/green] Audit logging enabled: {audit_log}")
        
        # Display startup information
        console.print(Panel.fit(
            "[bold blue]OpenAccess MCP Server[/bold blue]\n"
            f"Profiles: {profiles.absolute()}\n"
            f"Audit: {'enabled' if audit_log else 'default'}\n"
            f"Secrets: {'vault' if vault_addr else 'file' if secrets_dir else 'default'}",
            title="Server Configuration"
        ))
        
        # Create and run server
        server = OpenAccessMCPServer(profiles)
        
        if verbose:
            console.print("[dim]Starting server in verbose mode...[/dim]")
        
        asyncio.run(server.run())
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


@app.command()
def profiles(
    profiles_dir: Path = typer.Option(
        "./profiles",
        "--profiles",
        "-p",
        help="Directory containing profile JSON files"
    )
):
    """List available profiles."""
    try:
        if not profiles_dir.exists():
            console.print(f"[red]Error: Profiles directory not found: {profiles_dir}[/red]")
            sys.exit(1)
        
        profile_files = list(profiles_dir.glob("*.json"))
        
        if not profile_files:
            console.print(f"[yellow]No profile files found in {profiles_dir}[/yellow]")
            return
        
        table = Table(title=f"Profiles in {profiles_dir}")
        table.add_column("ID", style="cyan")
        table.add_column("Host", style="green")
        table.add_column("Port", style="blue")
        table.add_column("Protocols", style="yellow")
        table.add_column("Description", style="white")
        
        for profile_file in profile_files:
            try:
                import json
                with open(profile_file, "r") as f:
                    profile_data = json.load(f)
                
                table.add_row(
                    profile_data.get("id", "unknown"),
                    profile_data.get("host", "unknown"),
                    str(profile_data.get("port", 22)),
                    ", ".join(profile_data.get("protocols", [])),
                    profile_data.get("description", "")
                )
            except Exception as e:
                table.add_row(
                    profile_file.stem,
                    "[red]Error[/red]",
                    "",
                    "",
                    str(e)
                )
        
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def audit(
    log_file: Path = typer.Option(
        None,
        "--log-file",
        "-l",
        help="Audit log file path"
    )
):
    """Show audit log statistics."""
    try:
        audit_logger = get_audit_logger(log_file)
        stats = audit_logger.get_log_stats()
        
        if "error" in stats:
            console.print(f"[red]Error reading audit log: {stats['error']}[/red]")
            return
        
        table = Table(title="Audit Log Statistics")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Lines", str(stats["total_lines"]))
        table.add_row("File Size", f"{stats['file_size_bytes']} bytes")
        table.add_row("Last Modified", stats["last_modified"])
        
        console.print(table)
        
        # Show record counts by tool
        if stats["record_counts"]:
            tool_table = Table(title="Records by Tool")
            tool_table.add_column("Tool", style="cyan")
            tool_table.add_column("Result", style="yellow")
            tool_table.add_column("Count", style="green")
            
            for tool, results in stats["record_counts"].items():
                for result, count in results.items():
                    tool_table.add_row(tool, result, str(count))
            
            console.print(tool_table)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def verify(
    log_file: Path = typer.Option(
        None,
        "--log-file",
        "-l",
        help="Audit log file path"
    )
):
    """Verify audit log integrity."""
    try:
        audit_logger = get_audit_logger(log_file)
        verification = audit_logger.verify_log_integrity()
        
        if "error" in verification:
            console.print(f"[red]Verification failed: {verification['error']}[/red]")
            return
        
        table = Table(title="Audit Log Verification")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Records", str(verification["total_records"]))
        table.add_row("Chain Valid", "✓" if verification["chain_valid"] else "✗")
        table.add_row("First Record", verification["first_record"] or "N/A")
        table.add_row("Last Record", verification["last_record"] or "N/A")
        
        console.print(table)
        
        if verification["chain_valid"]:
            console.print("[green]✓ Audit log integrity verified[/green]")
        else:
            console.print("[red]✗ Audit log integrity check failed[/red]")
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def generate_keys(
    output_dir: Path = typer.Option(
        "./keys",
        "--output-dir",
        "-o",
        help="Output directory for generated keys"
    )
):
    """Generate new audit signing keys."""
    try:
        signer = create_audit_signer()
        private_key, public_key = signer.generate_keypair(output_dir)
        
        console.print(f"[green]✓[/green] Generated new audit keypair:")
        console.print(f"  Private key: {private_key}")
        console.print(f"  Public key: {public_key}")
        console.print(f"\n[yellow]Warning: Keep the private key secure![/yellow]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"[bold blue]OpenAccess MCP[/bold blue] version {__version__}")


if __name__ == "__main__":
    app()
