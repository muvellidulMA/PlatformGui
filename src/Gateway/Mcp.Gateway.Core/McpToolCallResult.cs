namespace Mcp.Gateway.Core;

public sealed record McpToolCallResult(string? RawResultJson, string? ErrorMessage, bool IsError);
