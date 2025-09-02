"""Audit CLI for OpenAccess MCP."""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import get_audit_logger, create_audit_signer

app = typer.Typer(help="OpenAccess MCP Audit Tools")
console = Console()


@app.command()
def verify(
    log_file: Path = typer.Argument(
        ...,
        help="Audit log file to verify"
    ),
    key_file: Optional[Path] = typer.Option(
        None,
        "--key-file",
        "-k",
        help="Public key file for verification"
    )
):
    """Verify the integrity of an audit log."""
    try:
        if not log_file.exists():
            console.print(f"[red]Error: Audit log file not found: {log_file}[/red]")
            sys.exit(1)
        
        audit_logger = get_audit_logger(log_file)
        verification = audit_logger.verify_log_integrity()
        
        if "error" in verification:
            console.print(f"[red]Verification failed: {verification['error']}[/red]")
            sys.exit(1)
        
        # Display verification results
        table = Table(title="Audit Log Verification Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Records", str(verification["total_records"]))
        table.add_row("Chain Valid", "✓" if verification["chain_valid"] else "✗")
        table.add_row("First Record", verification["first_record"] or "N/A")
        table.add_row("Last Record", verification["last_record"] or "N/A")
        
        console.print(table)
        
        if verification["chain_valid"]:
            console.print(Panel.fit(
                "[green]✓ Audit log integrity verified[/green]\n"
                "All records are properly signed and chained.",
                title="Verification Successful"
            ))
        else:
            console.print(Panel.fit(
                "[red]✗ Audit log integrity check failed[/red]\n"
                "The log may have been tampered with.",
                title="Verification Failed"
            ))
            sys.exit(1)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def stats(
    log_file: Path = typer.Argument(
        ...,
        help="Audit log file to analyze"
    )
):
    """Show statistics about an audit log."""
    try:
        if not log_file.exists():
            console.print(f"[red]Error: Audit log file not found: {log_file}[/red]")
            sys.exit(1)
        
        audit_logger = get_audit_logger(log_file)
        stats = audit_logger.get_log_stats()
        
        if "error" in stats:
            console.print(f"[red]Error reading audit log: {stats['error']}[/red]")
            sys.exit(1)
        
        # Display general statistics
        general_table = Table(title="General Statistics")
        general_table.add_column("Metric", style="cyan")
        general_table.add_column("Value", style="green")
        
        general_table.add_row("Total Lines", str(stats["total_lines"]))
        general_table.add_row("File Size", f"{stats['file_size_bytes']} bytes")
        general_table.add_row("Last Modified", stats["last_modified"])
        
        console.print(general_table)
        
        # Display record counts by tool and result
        if stats["record_counts"]:
            tool_table = Table(title="Records by Tool and Result")
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
        
        console.print(Panel.fit(
            f"[green]✓[/green] Generated new audit keypair:\n\n"
            f"Private key: [cyan]{private_key}[/cyan]\n"
            f"Public key: [cyan]{public_key}[/cyan]\n\n"
            f"[yellow]Warning: Keep the private key secure![/yellow]",
            title="Key Generation Successful"
        ))
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def extract_records(
    log_file: Path = typer.Argument(
        ...,
        help="Audit log file to extract from"
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Output file for extracted records"
    ),
    tool: Optional[str] = typer.Option(
        None,
        "--tool",
        "-t",
        help="Filter by specific tool"
    ),
    result: Optional[str] = typer.Option(
        None,
        "--result",
        "-r",
        help="Filter by specific result"
    ),
    actor: Optional[str] = typer.Option(
        None,
        "--actor",
        "-a",
        help="Filter by specific actor"
    )
):
    """Extract and filter audit records."""
    try:
        if not log_file.exists():
            console.print(f"[red]Error: Audit log file not found: {log_file}[/red]")
            sys.exit(1)
        
        audit_logger = get_audit_logger(log_file)
        
        # Read and filter records
        with open(log_file, "r") as f:
            lines = f.readlines()
        
        filtered_records = []
        
        for line in lines:
            try:
                import json
                data = json.loads(line.strip())
                
                # Skip header lines
                if "type" in data and data["type"] == "audit_log_header":
                    continue
                
                # Apply filters
                if tool and data.get("tool") != tool:
                    continue
                if result and data.get("result") != result:
                    continue
                if actor and data.get("actor") != actor:
                    continue
                
                filtered_records.append(data)
                
            except json.JSONDecodeError:
                continue
        
        # Display results
        console.print(f"[green]Found {len(filtered_records)} matching records[/green]")
        
        if filtered_records:
            table = Table(title="Filtered Records")
            table.add_column("Timestamp", style="cyan")
            table.add_column("Actor", style="green")
            table.add_column("Tool", style="yellow")
            table.add_column("Profile", style="blue")
            table.add_column("Result", style="white")
            
            for record in filtered_records[:10]:  # Show first 10
                table.add_row(
                    record.get("ts", "")[:19],  # Truncate timestamp
                    record.get("actor", ""),
                    record.get("tool", ""),
                    record.get("profile_id", ""),
                    record.get("result", "")
                )
            
            console.print(table)
            
            if len(filtered_records) > 10:
                console.print(f"[dim]... and {len(filtered_records) - 10} more records[/dim]")
        
        # Write to output file if specified
        if output_file:
            with open(output_file, "w") as f:
                for record in filtered_records:
                    f.write(json.dumps(record) + "\n")
            
            console.print(f"[green]✓[/green] Wrote {len(filtered_records)} records to {output_file}")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    app()
