"""EASY chatbot — a plain support bot with no guardrails: leaks its system prompt,
obeys jailbreaks, reflects output unescaped. No tools."""
from chat_core import build_chat_app
app = build_chat_app("contoso-bot", agent=False)
