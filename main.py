import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.status import Status
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from analyzers.url_analyzer import extract_urls, analyze_url

console = Console()
def print_banner():
    """Prints a clean ASCII-based banner."""
    banner_text = Text.assemble(
        ("\n PHISH", "bold white"),
        ("GUARD ", "bold red"),
        ("v1.0", "dim cyan"),
        ("\n SOC ANALYSIS FRAMEWORK", "grey50")
    )
    
    header = Panel(
        Align.center(banner_text),
        box=box.SQUARE,
        style="on #121212",
        padding=(1, 2)
    )
    console.print(header)
    console.print("[grey15]" + "—" * console.width + "[/grey15]")

def run_initialization():
    """Simulates system startup sequence."""
    with Status("[bold white][wait] Initializing engines...", spinner="dots", console=console) as status:
        time.sleep(0.6)
        status.update("[bold white][load] Loading URL Blacklists...")
        time.sleep(0.5)
        status.update("[bold white][conn] Connecting to Heuristic Engine...")
        time.sleep(0.5)
    console.print("[bold green][ready][/bold green] System initialized and ready.")

def main():
    # 1. Argument Check
    if len(sys.argv) < 2:
        console.print("\n[bold red][error][/bold red] Missing email file path.")
        console.print("[dim]Usage: python3 main.py <email_file>[/dim]\n")
        sys.exit()

    file_path = sys.argv[1]
    
    # 2. Setup
    print_banner()
    run_initialization()

    # 3. File Loading
    try:
        with Status(f"[grey70]Reading {file_path}...", spinner="dots"):
            with open(file_path, "r", encoding="utf-8") as file:
                email_content = file.read()
            time.sleep(0.4)
        console.print(f"[bold cyan][file][/bold cyan] Loaded: [white]{file_path}[/white]")
    except Exception as e:
        console.print(f"[bold red][error][/bold red] Could not read file: {e}")
        sys.exit()

    # 4. Email Preview
    preview_text = Text(email_content[:300].strip() + "...", style="grey62")
    console.print(
        Panel(
            preview_text,
            title="[bold yellow]RAW PREVIEW[/bold yellow]",
            title_align="left",
            border_style="grey30",
            padding=(1, 2)
        )
    )

    # 5. Extraction & Processing
    urls = extract_urls(email_content)

    if not urls:
        console.print("\n[bold green][clean][/bold green] No URLs detected in the email body.")
    else:
        console.print(f"\n[bold cyan][scan][/bold cyan] Found {len(urls)} URLs. Running reputation checks...\n")
        
        results_table = Table(
            title="[bold red]URL REPUTATION REPORT[/bold red]",
            title_justify="left",
            show_header=True,
            header_style="bold magenta",
            border_style="grey37",
            expand=True,
            box=box.SQUARE
        )
        
        results_table.add_column("ID", style="dim", width=4)
        results_table.add_column("Domain / Host", style="bold white", width=25)
        results_table.add_column("Full URL", style="cyan")
        results_table.add_column("Risk Score", justify="center")

        with Progress(
            TextColumn("[bold blue][{task.description}]"),
            BarColumn(bar_width=None, pulse_style="red"),
            TaskProgressColumn(),
            console=console,
            transient=True # Removes the progress bar when finished
        ) as progress:
            
            task = progress.add_task("analyzing", total=len(urls))
            
            for i, url in enumerate(urls, 1):
                # Simulated processing
                result = analyze_url(url)
                time.sleep(0.8) 
                
                # Risk Logic
                is_suspicious = any(x in url for x in ["xyz", "bit.ly", "short", "login"])
                risk_color = "red" if is_suspicious else "green"
                risk_text = "HIGH" if is_suspicious else "LOW"
                
                results_table.add_row(
                    f"{i:02d}",
                    result["full_domain"],
                    result["url"],
                    f"[{risk_color}]{risk_text}[/{risk_color}]"
                )
                progress.advance(task)

        # 6. Final Results
        console.print(results_table)

    console.print(f"\n[dim italic]Analysis finished at {time.strftime('%H:%M:%S')}[/dim italic]\n")

if __name__ == "__main__":
    main()