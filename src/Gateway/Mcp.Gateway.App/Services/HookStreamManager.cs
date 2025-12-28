using System.Collections.Concurrent;
using System.Text.Json;
using Mcp.Gateway.App.Options;
using Mcp.Gateway.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Mcp.Gateway.App.Services;

public sealed class HookStreamManager
{
    private sealed class HookStreamState
    {
        public HookStreamState(string hookId, string sessionId, string pollToolName, int pollIntervalMs, int maxEvents)
        {
            HookId = hookId;
            SessionId = sessionId;
            PollToolName = pollToolName;
            PollIntervalMs = pollIntervalMs;
            MaxEvents = maxEvents;
            Cancellation = new CancellationTokenSource();
        }

        public string HookId { get; }
        public string SessionId { get; }
        public string PollToolName { get; }
        public int PollIntervalMs { get; }
        public int MaxEvents { get; }
        public CancellationTokenSource Cancellation { get; }
    }

    private readonly IServiceProvider _serviceProvider;
    private readonly SseSessionManager _sse;
    private readonly ILogger<HookStreamManager> _logger;
    private readonly int _defaultPollIntervalMs;
    private readonly int _defaultMaxEvents;
    private readonly ConcurrentDictionary<string, HookStreamState> _streams = new(StringComparer.OrdinalIgnoreCase);

    public HookStreamManager(IServiceProvider serviceProvider, SseSessionManager sse, IOptions<GatewayOptions> options, ILogger<HookStreamManager> logger)
    {
        _serviceProvider = serviceProvider;
        _sse = sse;
        _logger = logger;
        _defaultPollIntervalMs = options.Value.HookPollingIntervalMs;
        _defaultMaxEvents = options.Value.HookPollingMaxEvents;
    }

    public void HandleToolResult(string toolName, string argsJson, McpToolCallResult result, string? sessionId)
    {
        if (string.IsNullOrWhiteSpace(sessionId))
            return;

        if (IsHookTool(toolName, "hook_start"))
        {
            if (!ShouldStream(argsJson, out var pollIntervalMs, out var maxEvents))
                return;

            if (!TryExtractHookId(result.RawResultJson, out var hookId))
            {
                _logger.LogWarning("HookId alinamadi, streaming baslatilmadi");
                return;
            }

            var pollToolName = ReplaceSuffix(toolName, "hook_start", "hook_poll");
            if (string.IsNullOrWhiteSpace(pollToolName))
                return;

            StartStreaming(hookId, sessionId, pollToolName, pollIntervalMs, maxEvents);
        }
        else if (IsHookTool(toolName, "hook_stop"))
        {
            if (TryExtractHookIdFromArgs(argsJson, out var hookId))
                StopStreaming(hookId);
        }
    }

    private void StartStreaming(string hookId, string sessionId, string pollToolName, int pollIntervalMs, int maxEvents)
    {
        if (!_sse.HasSession(sessionId))
            return;

        if (_streams.ContainsKey(hookId))
            return;

        var state = new HookStreamState(hookId, sessionId, pollToolName, pollIntervalMs, maxEvents);
        if (!_streams.TryAdd(hookId, state))
            return;

        _ = Task.Run(() => PollLoopAsync(state));
    }

    private void StopStreaming(string hookId)
    {
        if (_streams.TryRemove(hookId, out var state))
        {
            state.Cancellation.Cancel();
            state.Cancellation.Dispose();
        }
    }

    private async Task PollLoopAsync(HookStreamState state)
    {
        var ct = state.Cancellation.Token;
        while (!ct.IsCancellationRequested)
        {
            if (!_sse.HasSession(state.SessionId))
            {
                StopStreaming(state.HookId);
                return;
            }

            try
            {
                var pollArgs = JsonSerializer.Serialize(new { hookId = state.HookId, maxEvents = state.MaxEvents });
                var invoker = _serviceProvider.GetRequiredService<IWorkerToolInvoker>();
                var result = await invoker.InvokeAsync(state.PollToolName, pollArgs, 10000, state.SessionId, ct);
                if (!result.IsError && TryExtractEvents(result.RawResultJson, out var eventsJson))
                {
                    if (!string.IsNullOrWhiteSpace(eventsJson))
                    {
                        var notification = BuildNotification(state.HookId, eventsJson);
                        await _sse.SendAsync(state.SessionId, notification, ct);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Hook polling hatasi: {HookId}", state.HookId);
            }

            try
            {
                await Task.Delay(state.PollIntervalMs, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private bool ShouldStream(string argsJson, out int pollIntervalMs, out int maxEvents)
    {
        pollIntervalMs = _defaultPollIntervalMs;
        maxEvents = _defaultMaxEvents;

        if (string.IsNullOrWhiteSpace(argsJson))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(argsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            if (!doc.RootElement.TryGetProperty("stream", out var streamElement) ||
                streamElement.ValueKind != JsonValueKind.True)
                return false;

            if (doc.RootElement.TryGetProperty("pollIntervalMs", out var intervalElement) && intervalElement.TryGetInt32(out var interval))
                pollIntervalMs = interval;

            if (doc.RootElement.TryGetProperty("maxEvents", out var maxElement) && maxElement.TryGetInt32(out var max))
                maxEvents = max;

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryExtractHookId(string? rawResultJson, out string hookId)
    {
        hookId = string.Empty;
        if (string.IsNullOrWhiteSpace(rawResultJson))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(rawResultJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
            {
                var item = doc.RootElement[0];
                if (item.TryGetProperty("text", out var textElement) && textElement.ValueKind == JsonValueKind.String)
                {
                    var text = textElement.GetString();
                    if (!string.IsNullOrWhiteSpace(text))
                        return TryExtractHookIdFromPayload(text, out hookId);
                }
            }
            else if (doc.RootElement.ValueKind == JsonValueKind.Object)
            {
                return TryExtractHookIdFromPayload(doc.RootElement.GetRawText(), out hookId);
            }
        }
        catch (JsonException)
        {
        }

        return false;
    }

    private static bool TryExtractHookIdFromPayload(string payloadJson, out string hookId)
    {
        hookId = string.Empty;
        try
        {
            using var payloadDoc = JsonDocument.Parse(payloadJson);
            if (payloadDoc.RootElement.ValueKind == JsonValueKind.Object &&
                payloadDoc.RootElement.TryGetProperty("hookId", out var hookElement) &&
                hookElement.ValueKind == JsonValueKind.String)
            {
                hookId = hookElement.GetString() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(hookId);
            }
        }
        catch (JsonException)
        {
        }

        return false;
    }

    private static bool TryExtractHookIdFromArgs(string argsJson, out string hookId)
    {
        hookId = string.Empty;
        if (string.IsNullOrWhiteSpace(argsJson))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(argsJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("hookId", out var hookElement) &&
                hookElement.ValueKind == JsonValueKind.String)
            {
                hookId = hookElement.GetString() ?? string.Empty;
                return !string.IsNullOrWhiteSpace(hookId);
            }
        }
        catch (JsonException)
        {
        }

        return false;
    }

    private static bool TryExtractEvents(string? rawResultJson, out string eventsJson)
    {
        eventsJson = string.Empty;
        if (string.IsNullOrWhiteSpace(rawResultJson))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(rawResultJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0)
            {
                var item = doc.RootElement[0];
                if (item.TryGetProperty("text", out var textElement) && textElement.ValueKind == JsonValueKind.String)
                {
                    var payload = textElement.GetString();
                    if (string.IsNullOrWhiteSpace(payload))
                        return false;

                    using var payloadDoc = JsonDocument.Parse(payload);
                    if (payloadDoc.RootElement.TryGetProperty("events", out var eventsElement) && eventsElement.ValueKind == JsonValueKind.Array)
                    {
                        eventsJson = eventsElement.GetRawText();
                        return eventsJson.Length > 2;
                    }
                }
            }
        }
        catch (JsonException)
        {
        }

        return false;
    }

    private static string BuildNotification(string hookId, string eventsJson)
    {
        return $"{{\"jsonrpc\":\"2.0\",\"method\":\"frida/event\",\"params\":{{\"hookId\":\"{hookId}\",\"events\":{eventsJson}}}}}";
    }

    private static bool IsHookTool(string toolName, string suffix)
    {
        if (string.IsNullOrWhiteSpace(toolName))
            return false;

        if (toolName.Equals(suffix, StringComparison.OrdinalIgnoreCase))
            return true;

        return toolName.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase);
    }

    private static string ReplaceSuffix(string toolName, string fromSuffix, string toSuffix)
    {
        if (toolName.EndsWith("." + fromSuffix, StringComparison.OrdinalIgnoreCase))
            return toolName.Substring(0, toolName.Length - fromSuffix.Length) + toSuffix;

        if (toolName.Equals(fromSuffix, StringComparison.OrdinalIgnoreCase))
            return toSuffix;

        return string.Empty;
    }
}
