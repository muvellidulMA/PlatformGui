using System.Collections.Concurrent;

namespace Mcp.Worker.Frida.App.Services;

public sealed class FridaSessionStore
{
    private readonly ConcurrentDictionary<string, int> _sessions = new(StringComparer.OrdinalIgnoreCase);

    public string CreateSession(int pid)
    {
        var sessionId = Guid.NewGuid().ToString("N");
        _sessions[sessionId] = pid;
        return sessionId;
    }

    public bool TryGetPid(string sessionId, out int pid) => _sessions.TryGetValue(sessionId, out pid);
}
