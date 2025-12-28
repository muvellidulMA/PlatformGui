using Grpc.Net.Client;
using Mcp.Gateway.App.Options;
using Mcp.Gateway.Core;
using Mcp.Workers.Protocol;
using System.Text.Json;

namespace Mcp.Gateway.App.Services;

public sealed class WorkerRouter : IMcpToolProvider, IWorkerToolInvoker
{
    private sealed class WorkerEntry
    {
        public WorkerEntry(WorkerOptions options, Worker.WorkerClient client)
        {
            Options = options;
            Client = client;
        }

        public WorkerOptions Options { get; }
        public Worker.WorkerClient Client { get; }
    }

    private sealed class ToolRoute
    {
        public ToolRoute(WorkerEntry worker, string workerToolName, string description, string? inputSchemaJson)
        {
            Worker = worker;
            WorkerToolName = workerToolName;
            Description = description;
            InputSchemaJson = inputSchemaJson;
        }

        public WorkerEntry Worker { get; }
        public string WorkerToolName { get; }
        public string Description { get; }
        public string? InputSchemaJson { get; }
    }

    private readonly IReadOnlyList<WorkerEntry> _workers;
    private readonly ILogger<WorkerRouter> _logger;
    private readonly HookStreamManager _hookStreamManager;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private readonly TimeSpan _cacheTtl = TimeSpan.FromSeconds(15);
    private DateTimeOffset _lastRefresh = DateTimeOffset.MinValue;
    private IReadOnlyList<McpTool> _cachedTools = Array.Empty<McpTool>();
    private Dictionary<string, ToolRoute> _toolRoutes = new(StringComparer.OrdinalIgnoreCase);

    public WorkerRouter(IReadOnlyList<WorkerOptions> workerOptions, ILogger<WorkerRouter> logger, HookStreamManager hookStreamManager)
    {
        _logger = logger;
        _hookStreamManager = hookStreamManager;
        _workers = workerOptions
            .Where(o => !string.IsNullOrWhiteSpace(o.Address))
            .Select(o =>
            {
                var channel = GrpcChannel.ForAddress(o.Address);
                return new WorkerEntry(o, new Worker.WorkerClient(channel));
            })
            .ToArray();
    }

    public async Task<IReadOnlyList<McpTool>> ListToolsAsync(CancellationToken cancellationToken)
    {
        await RefreshToolsAsync(force: true, cancellationToken);
        return _cachedTools;
    }

    public async Task<McpToolCallResult> CallToolAsync(string name, string argsJson, int timeoutMs, string? sessionId, CancellationToken cancellationToken)
    {
        var result = await InvokeAsync(name, argsJson, timeoutMs, sessionId, cancellationToken);
        _hookStreamManager.HandleToolResult(name, argsJson, result, sessionId);
        return result;
    }

    public async Task<McpToolCallResult> InvokeAsync(string name, string argsJson, int timeoutMs, string? sessionId, CancellationToken cancellationToken)
    {
        await RefreshToolsAsync(force: false, cancellationToken);
        if (!_toolRoutes.TryGetValue(name, out var route))
        {
            await RefreshToolsAsync(force: true, cancellationToken);
            if (!_toolRoutes.TryGetValue(name, out route))
                return new McpToolCallResult(BuildErrorContent(BuildErrorPayload("NOT_FOUND", $"Arac bulunamadi: {name}")), null, true);
        }

        var request = new InvokeToolRequest
        {
            Name = route.WorkerToolName,
            ArgsJson = string.IsNullOrWhiteSpace(argsJson) ? "{}" : argsJson,
            TimeoutMs = timeoutMs,
            SessionId = sessionId ?? string.Empty
        };

        try
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs > 0 ? timeoutMs : 10000);
            var reply = await route.Worker.Client.InvokeToolAsync(request, deadline: deadline, cancellationToken: cancellationToken);
            if (!string.IsNullOrWhiteSpace(reply.Error))
                return new McpToolCallResult(BuildErrorContent(NormalizeErrorPayload(reply.Error, "RUNTIME")), null, true);

            return new McpToolCallResult(reply.ResultJson, null, false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Arac cagirma hatasi: {Tool}", name);
            return new McpToolCallResult(BuildErrorContent(BuildErrorPayload("RUNTIME", ex.Message)), null, true);
        }
    }

    private async Task RefreshToolsAsync(bool force, CancellationToken cancellationToken)
    {
        if (!force && DateTimeOffset.UtcNow - _lastRefresh < _cacheTtl && _cachedTools.Count > 0)
            return;

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            if (!force && DateTimeOffset.UtcNow - _lastRefresh < _cacheTtl && _cachedTools.Count > 0)
                return;

            var tools = new List<McpTool>();
            var routes = new Dictionary<string, ToolRoute>(StringComparer.OrdinalIgnoreCase);

            foreach (var worker in _workers)
            {
                var reply = await worker.Client.ListToolsAsync(new ListToolsRequest(), cancellationToken: cancellationToken);
                foreach (var tool in reply.Tools)
                {
                    var publicName = BuildPublicName(worker.Options, tool.Name);
                    if (routes.ContainsKey(publicName))
                    {
                        _logger.LogWarning("Ayni isimli arac bulundu: {Tool}", publicName);
                        continue;
                    }

                    routes[publicName] = new ToolRoute(worker, tool.Name, tool.Description, tool.InputSchemaJson);
                    tools.Add(new McpTool(publicName, tool.Description, tool.InputSchemaJson));
                }
            }

            _toolRoutes = routes;
            _cachedTools = tools;
            _lastRefresh = DateTimeOffset.UtcNow;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Arac listesi yenilenemedi");
            if (_cachedTools.Count == 0)
                _toolRoutes.Clear();
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    private static string BuildPublicName(WorkerOptions options, string toolName)
    {
        if (string.IsNullOrWhiteSpace(options.ToolPrefix))
            return toolName;

        return $"{options.ToolPrefix}{toolName}";
    }

    private static string BuildErrorPayload(string kind, string detail)
        => JsonSerializer.Serialize(new { ok = false, error = new { kind, detail } });

    private static string NormalizeErrorPayload(string errorText, string fallbackKind)
    {
        if (string.IsNullOrWhiteSpace(errorText))
            return BuildErrorPayload(fallbackKind, "bos hata");

        if (LooksLikeErrorPayload(errorText))
            return errorText;

        return BuildErrorPayload(fallbackKind, errorText);
    }

    private static bool LooksLikeErrorPayload(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            if (doc.RootElement.TryGetProperty("ok", out var okElement) && okElement.ValueKind == JsonValueKind.False)
                return true;

            return doc.RootElement.TryGetProperty("error", out _);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string BuildErrorContent(string payload)
    {
        var content = new[] { new ContentItem("text", payload) };
        return JsonSerializer.Serialize(content);
    }

    private sealed record ContentItem(string type, string text);
}
