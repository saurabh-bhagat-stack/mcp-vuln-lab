"""HARD agent — a multi-agent orchestrator exposing an A2A agent card, acting on
spoofed inter-agent messages, tool-chaining exfil, and persistent memory poisoning."""
from chat_core import build_chat_app
app = build_chat_app("contoso-orchestrator", agent=True, a2a=True)
