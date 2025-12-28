using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Mcp.Gateway.App.Services;

public sealed class SseSessionManager
{
    private sealed class SseSession
    {
        public SseSession(StreamWriter writer)
        {
            Writer = writer;
            WriteLock = new SemaphoreSlim(1, 1);
        }

        public StreamWriter Writer { get; }
        public SemaphoreSlim WriteLock { get; }
    }

    private readonly ConcurrentDictionary<string, SseSession> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly GatewayAuth _auth;

    public SseSessionManager(GatewayAuth auth)
    {
        _auth = auth;
    }

    public string Register(HttpContext context)
    {
        var sessionId = CreateSessionId();
        var writer = new StreamWriter(context.Response.Body, new UTF8Encoding(false), leaveOpen: true);
        var session = new SseSession(writer);

        _sessions[sessionId] = session;
        context.RequestAborted.Register(() => Remove(sessionId));
        return sessionId;
    }

    public bool HasSession(string sessionId) => _sessions.ContainsKey(sessionId);

    public async Task SendAsync(string sessionId, string payloadJson, CancellationToken cancellationToken)
    {
        if (!_sessions.TryGetValue(sessionId, out var session))
            return;

        await session.WriteLock.WaitAsync(cancellationToken);
        try
        {
            await session.Writer.WriteAsync($"data: {payloadJson}\n\n");
            await session.Writer.FlushAsync();
        }
        catch
        {
            Remove(sessionId);
        }
        finally
        {
            session.WriteLock.Release();
        }
    }

    public async Task SendEventAsync(string sessionId, string eventName, string data, CancellationToken cancellationToken)
    {
        if (!_sessions.TryGetValue(sessionId, out var session))
            return;

        await session.WriteLock.WaitAsync(cancellationToken);
        try
        {
            await session.Writer.WriteAsync($"event: {eventName}\n");
            await session.Writer.WriteAsync($"data: {data}\n\n");
            await session.Writer.FlushAsync();
        }
        catch
        {
            Remove(sessionId);
        }
        finally
        {
            session.WriteLock.Release();
        }
    }

    public string BuildEndpoint(string sessionId, HttpContext context)
    {
        var endpoint = $"/message?sessionId={WebUtility.UrlEncode(sessionId)}";
        var token = _auth.GetQueryToken(context);
        if (!string.IsNullOrWhiteSpace(token))
            endpoint += $"&token={WebUtility.UrlEncode(token)}";

        return endpoint;
    }

    public async Task WaitForDisconnectAsync(string sessionId, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
            Remove(sessionId);
        }
    }

    private void Remove(string sessionId)
    {
        if (_sessions.TryRemove(sessionId, out var session))
        {
            try
            {
                session.Writer.Dispose();
            }
            catch
            {
            }
        }
    }

    private static string CreateSessionId()
    {
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        var base64 = Convert.ToBase64String(bytes);
        return base64.TrimEnd('=').Replace('/', 'A').Replace('+', '-');
    }
}
