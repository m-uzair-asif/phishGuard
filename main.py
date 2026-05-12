import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.status import Status
from rich.progress import Progress, TextColumn, BarColumn
from rich.columns import Columns
from rich import box
import os

# Core Analysis Logic (Assuming these exist in your project)
from analyzers.url_analyzer import extract_urls, analyze_url, extract_headers

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

clear_screen()

def get_banner():
    """Returns the high-detail 3D ASCII banner."""
    # Using your provided 3D Isometric ASCII
    isometric_ascii = r"""
    ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
    ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                                                                                                                                                                                                                                                                                                            
    """
    banner_text = Text(isometric_ascii, style="bold green", overflow="ignore", no_wrap=True)
    
    # Adding a clean sub-header
    sub_header = Text("\n── SOC ANALYST TOOLKIT | THREAT INTELLIGENCE ENGINE ──", style="bold cyan")
    
    return Panel(
        Align.center(Text.assemble(banner_text, sub_header)),
        border_style="none",
        padding=(0, 1),
        # width=100
    )

def get_stats_panel(url_count):
    stats_table = Table.grid(expand=True)
    stats_table.add_column(style="cyan", justify="left")
    stats_table.add_column(style="white", justify="right")
    stats_table.add_row("System Status:", "[bold green]PROTECTED[/bold green]")
    stats_table.add_row("Active URLs:", f"{url_count}")
    stats_table.add_row("Session ID:", f"THREAT-{int(time.time()) % 10000}")
    
    return Panel(stats_table, title="[bold white]TELEMETRY[/bold white]", border_style="red")

def main():
    if len(sys.argv) < 2:
        console.print("\n[bold red]✘ ERROR:[/bold red] Target email file not specified.")
        sys.exit()

    file_path = sys.argv[1]
    
    # 1. Initialization
    console.print(get_banner())
    
    with Status("[bold white]Parsing headers...", spinner="point", console=console):
        time.sleep(0.5)
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                email_content = file.read()
        except Exception as e:
            console.print(f"[bold red]CRITICAL FILE ERROR:[/bold red] {e}")
            sys.exit()

    urls = extract_urls(email_content)
    headers = extract_headers(file_path)

    preview = Panel(
        Text(email_content[:280].strip() + "...", style="grey62"),
        title="[bold yellow]RAW CONTENT INSPECTOR[/bold yellow]",
        border_style="grey30",
        expand=True
    )
    
    console.print(Columns([preview, get_stats_panel(len(urls))], expand=True))

    headers_table = Table(
        title="[bold yellow]EMAIL HEADERS[/bold yellow]",
        border_style="grey30",
        box=box.MINIMAL,
        expand=True
    )

    headers_table.add_column(
        "Header",
        style="bold cyan",
        width=25
    )

    headers_table.add_column(
        "Value",
        style="white"
    )

    for item in headers:
        status = item["status"]

        if "failed" in status.lower():
            status = f"[bold red]{status}[/bold red]"

        elif "suspicious" in status.lower():
            status = f"[bold yellow]{status}[/bold yellow]"

        elif "pass" in status.lower():
            status = f"[bold green]{status}[/bold green]"

        headers_table.add_row(
            item["field"],
            item["value"],
            status
    )

    console.print(headers_table)

    if not urls:
        console.print("\n[bold green]✔[/bold green] [white]Zero suspicious links identified in content body.[/white]")
    else:
        # 3. Threat Table
        results_table = Table(
            show_header=True,
            header_style="bold white on red",
            border_style="grey37",
            expand=True,
            box=box.MINIMAL
        )
        
        results_table.add_column("RANK", width=6, justify="center")
        results_table.add_column("DOMAIN AUTHORITY", style="bold white")
        results_table.add_column("URL STRING", style="dim", ratio=2)
        results_table.add_column("THREAT SCORE", justify="right")

        with Progress(
            TextColumn("[bold red]>[/bold red] Investigating: [cyan]{task.fields[url]}"),
            BarColumn(bar_width=None, pulse_style="bright_red"),
            console=console,
            transient=True 
        ) as progress:
            
            task = progress.add_task("investigating", total=len(urls), url="")
            
            for i, url in enumerate(urls, 1):
                progress.update(task, url=url[:35])
                result = analyze_url(url)
                time.sleep(0.7) 
                
                # Simple Risk Heuristic
                suspicious = any(k in url.lower() for k in ["secure", "update", "verify", "bit.ly", "cmd"])
                risk_label = "[bold red]MALICIOUS[/bold red]" if suspicious else "[bold green]CLEAN[/bold green]"
                
                results_table.add_row(
                    f"#{i}",
                    result["full_domain"],
                    url,
                    risk_label
                )
                progress.advance(task)

        console.print(results_table)

    # 4. Footer
    console.print(Align.right(f"[dim]ANALYSIS COMPLETE | {time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]"))

if __name__ == "__main__":
    main()