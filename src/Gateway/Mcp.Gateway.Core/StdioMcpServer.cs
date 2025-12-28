using System.Text;
using Microsoft.Extensions.Logging;

namespace Mcp.Gateway.Core;

public sealed class StdioMcpServer
{
    private readonly McpMessageHandler _handler;
    private readonly ILogger<StdioMcpServer> _logger;

    public StdioMcpServer(McpMessageHandler handler, ILogger<StdioMcpServer> logger)
    {
        _handler = handler;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("STDIO MCP sunucusu basladi.");
        var input = Console.OpenStandardInput();
        var output = Console.OpenStandardOutput();

        while (!cancellationToken.IsCancellationRequested)
        {
            var message = await ReadMessageAsync(input, cancellationToken);
            if (message == null)
                break;

            var responseJson = await _handler.HandleAsync(message, "stdio", cancellationToken);
            if (!string.IsNullOrWhiteSpace(responseJson))
                await WriteMessageAsync(output, responseJson, cancellationToken);
        }

        _logger.LogInformation("STDIO MCP sunucusu kapandi.");
    }

    private static async Task<string?> ReadMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        int? contentLength = null;
        while (true)
        {
            var line = await ReadLineAsync(stream, cancellationToken);
            if (line == null)
                return null;

            if (line.Length == 0)
                break;

            if (line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                var value = line.Substring("Content-Length:".Length).Trim();
                if (int.TryParse(value, out var length))
                    contentLength = length;
            }
        }

        if (contentLength == null || contentLength <= 0)
            return null;

        var buffer = new byte[contentLength.Value];
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), cancellationToken);
            if (read == 0)
                return null;

            totalRead += read;
        }

        return Encoding.UTF8.GetString(buffer);
    }

    private static async Task<string?> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new List<byte>();
        var oneByte = new byte[1];

        while (true)
        {
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken);
            if (read == 0)
                return null;

            var b = oneByte[0];
            if (b == '\n')
                break;

            if (b != '\r')
                buffer.Add(b);
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private async Task WriteMessageAsync(Stream stream, string json, CancellationToken cancellationToken)
    {
        var payload = Encoding.UTF8.GetBytes(json);
        var header = Encoding.ASCII.GetBytes($"Content-Length: {payload.Length}\r\n\r\n");

        await stream.WriteAsync(header.AsMemory(0, header.Length), cancellationToken);
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }
}
