using System.Text.Json;
using Mcp.Worker.Frida.App.Options;

namespace Mcp.Worker.Frida.App.Services;

public sealed class FridaToolPolicy
{
    private readonly HashSet<string> _blocked;

    public FridaToolPolicy(FridaOptions options)
    {
        _blocked = new HashSet<string>(options.BlockedTools ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }

    public ToolPolicyDecision Evaluate(string toolName, string? argsJson)
    {
        if (_blocked.Contains(toolName))
            return new ToolPolicyDecision(false, "deny", "blocked");

        var risk = toolName switch
        {
            "script_load" => "high",
            "script_unload" => "high",
            "script_message_poll" => "high",
            "script_post" => "high",
            "rpc_call" => "high",
            "write_memory" => "high",
            "call_function" => "high",
            "spawn" => "high",
            "resume" => "high",
            "kill" => "high",
            "hook_start" => "high",
            "hook_stop" => "high",
            "hook_poll" => "high",
            "set_breakpoint" => "high",
            "read_memory" => "medium",
            "read_string" => "medium",
            "detach" => "low",
            "self_test" => "low",
            _ => "low"
        };

        var detail = string.Empty;
        if (string.Equals(toolName, "read_string", StringComparison.OrdinalIgnoreCase))
        {
            var encoding = TryGetEncoding(argsJson);
            if (!string.IsNullOrWhiteSpace(encoding))
                detail = $"encoding={encoding}";
        }

        return new ToolPolicyDecision(true, risk, detail);
    }

    private static string? TryGetEncoding(string? argsJson)
    {
        if (string.IsNullOrWhiteSpace(argsJson))
            return null;

        try
        {
            using var doc = JsonDocument.Parse(argsJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            if (doc.RootElement.TryGetProperty("encoding", out var encElement) && encElement.ValueKind == JsonValueKind.String)
                return encElement.GetString();
        }
        catch (JsonException)
        {
        }

        return null;
    }
}

public sealed record ToolPolicyDecision(bool Allowed, string Risk, string Detail);
