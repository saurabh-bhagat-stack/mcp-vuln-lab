"""MEDIUM agent — a chatbot WITH tools: prompt-injection -> tool-call hijack,
attacker-directed fetch (exfil), client-controllable system prompt, cross-turn memory."""
from chat_core import build_chat_app
app = build_chat_app("contoso-agent", agent=True)
