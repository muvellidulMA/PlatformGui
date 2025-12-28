using System.Buffers;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace Mcp.Gateway.Core;

public sealed class McpMessageHandler
{
    private static readonly JsonWriterOptions WriterOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    private readonly IMcpToolProvider _toolProvider;
    private readonly McpServerInfo _serverInfo;
    private readonly int _defaultToolTimeoutMs;

    public McpMessageHandler(IMcpToolProvider toolProvider, McpServerInfo serverInfo, int defaultToolTimeoutMs)
    {
        _toolProvider = toolProvider;
        _serverInfo = serverInfo;
        _defaultToolTimeoutMs = defaultToolTimeoutMs;
    }

    public async Task<string?> HandleAsync(string requestJson, string? sessionId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(requestJson))
            return BuildError(null, -32600, "Invalid Request");

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(requestJson);
        }
        catch (JsonException)
        {
            return BuildError(null, -32700, "Parse error");
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return BuildError(null, -32600, "Invalid Request");

            var root = doc.RootElement;
            var hasId = root.TryGetProperty("id", out var idElement);
            var hasMethod = root.TryGetProperty("method", out var methodElement);

            if (!hasMethod || methodElement.ValueKind != JsonValueKind.String)
                return BuildError(hasId ? idElement : null, -32600, "Invalid Request");

            var method = methodElement.GetString() ?? string.Empty;
            var hasParams = root.TryGetProperty("params", out var paramsElement);

            if (!hasId)
            {
                if (method is "notifications/initialized" or "initialized")
                    return null;
            }

            switch (method)
            {
                case "initialize":
                    return hasId ? BuildInitializeResult(idElement) : null;
                case "notifications/initialized":
                case "initialized":
                    return null;
                case "tools/list":
                    return hasId ? await BuildToolsListResultAsync(idElement, cancellationToken) : null;
                case "tools/call":
                    return hasId
                        ? await BuildToolsCallResultAsync(idElement, hasParams ? paramsElement : (JsonElement?)null, sessionId, cancellationToken)
                        : null;
                default:
                    return hasId ? BuildError(idElement, -32601, "Method not found") : null;
            }
        }
    }

    private string BuildInitializeResult(JsonElement idElement)
    {
        return BuildResult(idElement, writer =>
        {
            writer.WriteString("protocolVersion", _serverInfo.ProtocolVersion);
            writer.WritePropertyName("capabilities");
            writer.WriteStartObject();
            writer.WritePropertyName("tools");
            writer.WriteStartObject();
            writer.WriteEndObject();
            writer.WriteEndObject();
            writer.WritePropertyName("serverInfo");
            writer.WriteStartObject();
            writer.WriteString("name", _serverInfo.Name);
            writer.WriteString("version", _serverInfo.Version);
            writer.WriteEndObject();
            writer.WriteString("instructions", string.Empty);
        });
    }

    private async Task<string> BuildToolsListResultAsync(JsonElement idElement, CancellationToken cancellationToken)
    {
        var tools = await _toolProvider.ListToolsAsync(cancellationToken);
        return BuildResult(idElement, writer =>
        {
            writer.WritePropertyName("tools");
            writer.WriteStartArray();
            foreach (var tool in tools)
            {
                writer.WriteStartObject();
                writer.WriteString("name", tool.Name);
                writer.WriteString("description", tool.Description);
                writer.WritePropertyName("inputSchema");
                WriteInputSchema(writer, tool.InputSchemaJson);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        });
    }

    private async Task<string> BuildToolsCallResultAsync(
        JsonElement idElement,
        JsonElement? paramsElement,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        if (paramsElement == null || paramsElement.Value.ValueKind != JsonValueKind.Object)
            return BuildError(idElement, -32602, "Invalid params");

        var paramsObject = paramsElement.Value;
        if (!paramsObject.TryGetProperty("name", out var nameElement) || nameElement.ValueKind != JsonValueKind.String)
            return BuildError(idElement, -32602, "Invalid params");

        var name = nameElement.GetString() ?? string.Empty;
        var argsJson = "{}";
        if (paramsObject.TryGetProperty("arguments", out var argumentsElement))
            argsJson = argumentsElement.GetRawText();

        var timeoutMs = _defaultToolTimeoutMs;
        if (paramsObject.TryGetProperty("timeoutMs", out var timeoutElement) && timeoutElement.TryGetInt32(out var timeoutValue))
            timeoutMs = timeoutValue;

        var result = await _toolProvider.CallToolAsync(name, argsJson, timeoutMs, sessionId, cancellationToken);

        return BuildResult(idElement, writer =>
        {
            WriteToolCallContent(writer, result);
            writer.WriteBoolean("isError", result.IsError);
        });
    }

    private static void WriteInputSchema(Utf8JsonWriter writer, string? inputSchemaJson)
    {
        if (!string.IsNullOrWhiteSpace(inputSchemaJson))
        {
            try
            {
                using var schemaDoc = JsonDocument.Parse(inputSchemaJson);
                schemaDoc.RootElement.WriteTo(writer);
                return;
            }
            catch (JsonException)
            {
            }
        }

        writer.WriteStartObject();
        writer.WriteString("type", "object");
        writer.WriteEndObject();
    }

    private static void WriteToolCallContent(Utf8JsonWriter writer, McpToolCallResult result)
    {
        writer.WritePropertyName("content");
        if (!string.IsNullOrWhiteSpace(result.RawResultJson))
        {
            try
            {
                using var doc = JsonDocument.Parse(result.RawResultJson);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    doc.RootElement.WriteTo(writer);
                    return;
                }
            }
            catch (JsonException)
            {
            }
        }

        var text = result.ErrorMessage ?? result.RawResultJson ?? string.Empty;
        writer.WriteStartArray();
        writer.WriteStartObject();
        writer.WriteString("type", "text");
        writer.WriteString("text", text);
        writer.WriteEndObject();
        writer.WriteEndArray();
    }

    private static string BuildError(JsonElement? idElement, int code, string message)
    {
        return BuildResponse(idElement, writer =>
        {
            writer.WritePropertyName("error");
            writer.WriteStartObject();
            writer.WriteNumber("code", code);
            writer.WriteString("message", message);
            writer.WriteEndObject();
        });
    }

    private static string BuildResult(JsonElement idElement, Action<Utf8JsonWriter> writeResult)
    {
        return BuildResponse(idElement, writer =>
        {
            writer.WritePropertyName("result");
            writer.WriteStartObject();
            writeResult(writer);
            writer.WriteEndObject();
        });
    }

    private static string BuildResponse(JsonElement? idElement, Action<Utf8JsonWriter> writePayload)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using var writer = new Utf8JsonWriter(buffer, WriterOptions);

        writer.WriteStartObject();
        writer.WriteString("jsonrpc", "2.0");
        writer.WritePropertyName("id");
        if (idElement.HasValue)
            idElement.Value.WriteTo(writer);
        else
            writer.WriteNullValue();

        writePayload(writer);
        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
