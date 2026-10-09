"""
MEDIUM MCP target — a "SharePoint/Graph connector" MCP server. Auth is *present*
(a Bearer token is required) but validated nowhere: any token is trusted, objects
are not scoped to the caller, and results leak more than they should.

Enter any token in your MCP scanner (e.g. `Bearer alice-token`).
"""
from mcp_core import ServerSpec, Tool, build_app
import vulnlib as V

TOOLS = [
    Tool("list_items", "List the documents you can access.",
         {"type": "object", "properties": {}}, V.list_items),
    Tool("get_item", "Get a document by its item id.",
         V.S(itemId=V.STR("item id")), V.get_item),            # IDOR / BOLA
    Tool("graph_query", "Query the drive with an OData $filter.",
         V.S(filter=V.STR("OData filter")), V.graph_query),     # OData injection
    Tool("get_share_link", "Create a shareable link for a document.",
         V.S(itemId=V.STR("item id")), V.get_share_link),       # SAS / pre-auth URL exposure
    Tool("search_notes", "Search notes; `limit` controls how many to return.",
         V.S(query=V.STR("query"), limit=V.INT("max results")), V.search_notes),  # unbounded
    Tool("save_note", "Save a note (title + content).",
         V.S(title=V.STR("title"), content=V.STR("note body")), V.save_note),      # stored injection
    Tool("format_note", "Format a note for display.",
         V.S(content=V.STR("note body")), V.format_note),       # SSE frame splitting
    Tool("vector_search", "Semantic search over the knowledge base.",
         V.S(query=V.STR("query"), namespace=V.STR("namespace"), filter=V.STR("metadata filter")),
         V.vector_search),                                       # vector scope bypass
    Tool("assistant_help", "Get contextual help from the assistant.",
         V.S(topic=V.STR("topic")), V.assistant_help),           # reverse-request abuse
]

spec = ServerSpec(name="contoso-graph-connector (medium)", auth="any-token",
                  tools=TOOLS, cors_wildcard_creds=True, rate_limit_after=0)
app = build_app(spec)
