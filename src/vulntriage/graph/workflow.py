from langgraph.graph import END, StateGraph

from . import nodes
from .state import TriageState


def build_graph():
    g = StateGraph(TriageState)
    for name in ["parse", "enrich", "add_context", "rank", "remediate", "review_gate"]:
        g.add_node(name, getattr(nodes, name))
    g.set_entry_point("parse")
    g.add_edge("parse", "enrich")
    g.add_edge("enrich", "add_context")
    g.add_edge("add_context", "rank")
    g.add_edge("rank", "remediate")
    g.add_edge("remediate", "review_gate")
    g.add_edge("review_gate", END)
    return g.compile()
