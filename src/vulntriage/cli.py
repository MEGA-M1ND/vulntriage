from pathlib import Path

import typer
from dotenv import load_dotenv

from .graph.workflow import build_graph
from .report import to_markdown

app = typer.Typer(add_completion=False)

@app.command()
def run(scan: Path, out: Path = Path("report.md"), top: int = 10):
    """Triage a Trivy JSON scan and write a patch plan."""
    load_dotenv()
    state = build_graph().invoke({"scan_path": str(scan)})
    out.write_text(to_markdown(state["findings"], top))
    typer.echo(f"Wrote {out} ({len(state['findings'])} findings)")
    for e in state.get("errors", []):
        typer.echo(f"warning: {e}", err=True)
