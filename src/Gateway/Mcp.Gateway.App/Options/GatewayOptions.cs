namespace Mcp.Gateway.App.Options;

public sealed class GatewayOptions
{
    public string? AuthToken { get; set; }
    public string ServerName { get; set; } = "McpGateway";
    public string ServerVersion { get; set; } = "0.1.0";
    public string ProtocolVersion { get; set; } = "2024-11-05";
    public int DefaultToolTimeoutMs { get; set; } = 10000;
    public int HookPollingIntervalMs { get; set; } = 500;
    public int HookPollingMaxEvents { get; set; } = 50;
    public HttpOptions Http { get; set; } = new();
}

public sealed class HttpOptions
{
    public bool Enabled { get; set; } = true;
    public string Url { get; set; } = "http://0.0.0.0:13338";
}
