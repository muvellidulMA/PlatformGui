using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Mcp.Worker.Frida.App.Options;

namespace Mcp.Worker.Frida.App.Services;

public sealed class FridaSessionManager
{
    private sealed class SessionInstance
    {
        public SessionInstance(string sessionId, int pid, Process process, StreamWriter input)
        {
            SessionId = sessionId;
            Pid = pid;
            Process = process;
            Input = input;
        }

        public string SessionId { get; }
        public int Pid { get; }
        public Process Process { get; }
        public StreamWriter Input { get; }
        public ConcurrentDictionary<string, TaskCompletionSource<string>> Pending { get; } = new(StringComparer.OrdinalIgnoreCase);
        public CancellationTokenSource Cancellation { get; } = new();
    }

    private readonly ConcurrentDictionary<string, SessionInstance> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly FridaOptions _options;
    private readonly ILogger<FridaSessionManager> _logger;

    public FridaSessionManager(FridaOptions options, ILogger<FridaSessionManager> logger)
    {
        _options = options;
        _logger = logger;
        CleanupTempFiles("frida_session_", TimeSpan.FromHours(24));
    }

    public bool HasSession(string sessionId) => _sessions.ContainsKey(sessionId);

    public void StartSession(string sessionId, int pid)
    {
        if (_sessions.ContainsKey(sessionId))
            return;

        var process = StartHostProcess(pid, sessionId);
        var instance = new SessionInstance(sessionId, pid, process, process.StandardInput);
        _sessions[sessionId] = instance;

        process.EnableRaisingEvents = true;
        process.Exited += (_, _) => OnProcessExit(instance);

        _ = Task.Run(() => ReadOutputAsync(instance));
        _ = Task.Run(() => ReadErrorAsync(instance));
    }

    public bool StopSession(string sessionId)
    {
        if (!_sessions.TryRemove(sessionId, out var instance))
            return false;

        try
        {
            instance.Input.WriteLine("{\"op\":\"detach\"}");
            instance.Input.Flush();
        }
        catch
        {
        }

        instance.Cancellation.Cancel();
        TryKill(instance.Process);
        instance.Cancellation.Dispose();
        return true;
    }

    public async Task<JsonElement> CallAsync(string sessionId, string op, JsonElement args, int timeoutMs, CancellationToken cancellationToken)
    {
        if (!_sessions.TryGetValue(sessionId, out var instance))
            throw new InvalidOperationException("session bulunamadi");

        var id = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!instance.Pending.TryAdd(id, tcs))
            throw new InvalidOperationException("session istek kaydi basarisiz");

        var payload = JsonSerializer.Serialize(new { id, op, args });
        await SendCommandAsync(instance, payload, cancellationToken);

        string line;
        try
        {
            line = await tcs.Task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), cancellationToken);
        }
        catch (Exception ex)
        {
            instance.Pending.TryRemove(id, out _);
            throw new InvalidOperationException($"session timeout: {ex.Message}");
        }

        return ParseResponse(line);
    }

    private Process StartHostProcess(int pid, string sessionId)
    {
        var hostPath = ResolveHostPath();
        if (string.IsNullOrWhiteSpace(hostPath))
            throw new InvalidOperationException("frida_session_host.py bulunamadi");

        var psi = new ProcessStartInfo
        {
            FileName = _options.PythonPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var arg in _options.PythonArgs)
            psi.ArgumentList.Add(arg);

        psi.ArgumentList.Add(hostPath);
        psi.ArgumentList.Add("--pid");
        psi.ArgumentList.Add(pid.ToString());
        psi.ArgumentList.Add("--session-id");
        psi.ArgumentList.Add(sessionId);
        psi.ArgumentList.Add("--device");
        psi.ArgumentList.Add(_options.Device);

        if (!string.IsNullOrWhiteSpace(_options.RemoteHost))
        {
            psi.ArgumentList.Add("--remote-host");
            psi.ArgumentList.Add(_options.RemoteHost);
        }

        psi.ArgumentList.Add("--timeout-ms");
        psi.ArgumentList.Add(_options.TimeoutMs.ToString());

        var process = new Process { StartInfo = psi };
        process.Start();
        return process;
    }

    private async Task ReadOutputAsync(SessionInstance instance)
    {
        try
        {
            while (!instance.Cancellation.IsCancellationRequested && !instance.Process.HasExited)
            {
                var line = await instance.Process.StandardOutput.ReadLineAsync();
                if (line == null)
                    break;

                if (!TryHandleResponse(instance, line))
                    _logger.LogInformation("Session event: {SessionId} {Line}", instance.SessionId, line);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Session stdout hatasi: {SessionId}", instance.SessionId);
        }
    }

    private async Task ReadErrorAsync(SessionInstance instance)
    {
        try
        {
            while (!instance.Cancellation.IsCancellationRequested && !instance.Process.HasExited)
            {
                var line = await instance.Process.StandardError.ReadLineAsync();
                if (line == null)
                    break;

                _logger.LogWarning("Session stderr: {SessionId} {Line}", instance.SessionId, line);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Session stderr hatasi: {SessionId}", instance.SessionId);
        }
    }

    private void OnProcessExit(SessionInstance instance)
    {
        foreach (var pair in instance.Pending)
            pair.Value.TrySetCanceled();

        _sessions.TryRemove(instance.SessionId, out _);
    }

    private static async Task SendCommandAsync(SessionInstance instance, string payload, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await instance.Input.WriteLineAsync(payload);
        await instance.Input.FlushAsync();
    }

    private static bool TryHandleResponse(SessionInstance instance, string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (!doc.RootElement.TryGetProperty("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String)
                return false;

            if (!string.Equals(typeElement.GetString(), "response", StringComparison.OrdinalIgnoreCase))
                return false;

            if (!doc.RootElement.TryGetProperty("id", out var idElement) || idElement.ValueKind != JsonValueKind.String)
                return false;

            var id = idElement.GetString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(id))
                return false;

            if (!instance.Pending.TryRemove(id, out var tcs))
                return false;

            tcs.TrySetResult(line);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static JsonElement ParseResponse(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var okElement) && okElement.ValueKind == JsonValueKind.True)
        {
            if (root.TryGetProperty("data", out var dataElement))
                return dataElement.Clone();

            return default;
        }

        if (root.TryGetProperty("error", out var errorElement))
            throw new InvalidOperationException(errorElement.GetString() ?? "session error");

        throw new InvalidOperationException("session error");
    }

    private string ResolveHostPath()
    {
        if (!string.IsNullOrWhiteSpace(_options.SessionHostPath))
            return _options.SessionHostPath;

        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, "Scripts", "frida_session_host.py");
        if (File.Exists(candidate))
            return candidate;

        var fallback = Path.Combine(baseDir, "frida_session_host.py");
        return File.Exists(fallback) ? fallback : string.Empty;
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(true);
        }
        catch
        {
        }
    }

    private static void CleanupTempFiles(string prefix, TimeSpan maxAge)
    {
        try
        {
            var temp = Path.GetTempPath();
            var files = Directory.GetFiles(temp, $"{prefix}*.js");
            var cutoff = DateTime.UtcNow - maxAge;
            foreach (var file in files)
            {
                try
                {
                    var info = new FileInfo(file);
                    if (info.LastWriteTimeUtc < cutoff)
                        info.Delete();
                }
                catch
                {
                }
            }
        }
        catch
        {
        }
    }
}
