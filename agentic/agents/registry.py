"""
Agent Registry
===============
Maps agent names to their class implementations. Used by the orchestrator
to dynamically dispatch tasks to the correct agent.

To register a new agent:
1. Create a class inheriting from BaseAgent
2. Add it to the AGENT_REGISTRY dict below
"""

from agentic.agents.base import BaseAgent
from agentic.agents.cve_lookup import CVELookupAgent
from agentic.agents.asset_discovery import AssetDiscoveryAgent

# Name → Agent class mapping
AGENT_REGISTRY: dict[str, type[BaseAgent]] = {
    "cve_lookup": CVELookupAgent,
    "asset_discovery": AssetDiscoveryAgent,
}


def get_agent(name: str, **kwargs) -> BaseAgent:
    """Instantiate an agent by name."""
    if name not in AGENT_REGISTRY:
        raise ValueError(f"Unknown agent: {name}. Available: {list(AGENT_REGISTRY.keys())}")
    return AGENT_REGISTRY[name](**kwargs)


def list_agents() -> list[str]:
    """Return all registered agent names."""
    return list(AGENT_REGISTRY.keys())
