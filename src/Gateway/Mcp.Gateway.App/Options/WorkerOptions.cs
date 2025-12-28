namespace Mcp.Gateway.App.Options;

public sealed class WorkerOptions
{
    public string Id { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public string? ToolPrefix { get; set; }
}
