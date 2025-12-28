namespace Mcp.Gateway.Core;

public interface IMcpToolProvider
{
    Task<IReadOnlyList<McpTool>> ListToolsAsync(CancellationToken cancellationToken);
    Task<McpToolCallResult> CallToolAsync(string name, string argsJson, int timeoutMs, string? sessionId, CancellationToken cancellationToken);
}
