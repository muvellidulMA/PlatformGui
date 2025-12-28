using Mcp.Gateway.Core;

namespace Mcp.Gateway.App.Services;

public interface IWorkerToolInvoker
{
    Task<McpToolCallResult> InvokeAsync(string name, string argsJson, int timeoutMs, string? sessionId, CancellationToken cancellationToken);
}
