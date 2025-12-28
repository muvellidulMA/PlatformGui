using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Mcp.Worker.Frida.App.Options;

namespace Mcp.Worker.Frida.App.Services;

public sealed class FridaScriptManager
{
    private sealed class ScriptInstance
    {
        public ScriptInstance(string scriptId, int pid, Process process, string scriptPath, StreamWriter input)
        {
            ScriptId = scriptId;
            Pid = pid;
            Process = process;
            ScriptPath = scriptPath;
            Input = input;
        }

        public string ScriptId { get; }
        public int Pid { get; }
        public Process Process { get; }
        public string ScriptPath { get; }
        public StreamWriter Input { get; }
        public bool IsExited { get; set; }
        public int ExitCode { get; set; }
        public ConcurrentQueue<string> Events { get; } = new();
        public ConcurrentDictionary<string, TaskCompletionSource<string>> PendingRpc { get; } = new(StringComparer.OrdinalIgnoreCase);
        public CancellationTokenSource Cancellation { get; } = new();
    }

    private readonly ConcurrentDictionary<string, ScriptInstance> _scripts = new(StringComparer.OrdinalIgnoreCase);
    private readonly FridaOptions _options;
    private readonly ILogger<FridaScriptManager> _logger;

    public FridaScriptManager(FridaOptions options, ILogger<FridaScriptManager> logger)
    {
        _options = options;
        _logger = logger;
        CleanupTempFiles("frida_script_", TimeSpan.FromHours(24));
    }

    public string StartScript(int pid, string source)
    {
        var scriptId = Guid.NewGuid().ToString("N");
        var scriptPath = Path.Combine(Path.GetTempPath(), $"frida_script_{scriptId}.js");
        File.WriteAllText(scriptPath, source, new UTF8Encoding(false));

        var process = StartHostProcess(pid, scriptId, scriptPath);
        var instance = new ScriptInstance(scriptId, pid, process, scriptPath, process.StandardInput);
        _scripts[scriptId] = instance;

        process.EnableRaisingEvents = true;
        process.Exited += (_, _) => OnProcessExit(instance);

        _ = Task.Run(() => ReadOutputAsync(instance));
        _ = Task.Run(() => ReadErrorAsync(instance));

        return scriptId;
    }

    public IReadOnlyList<string> PollMessages(string scriptId, int maxEvents)
    {
        if (!_scripts.TryGetValue(scriptId, out var instance))
            return Array.Empty<string>();

        var list = new List<string>(Math.Max(1, maxEvents));
        for (var i = 0; i < maxEvents; i++)
        {
            if (!instance.Events.TryDequeue(out var evt))
                break;

            list.Add(evt);
        }

        if (instance.IsExited && instance.Events.IsEmpty)
        {
            if (_scripts.TryRemove(scriptId, out var removed))
                FinalizeScript(removed);
        }

        return list;
    }

    public async Task<JsonElement> RpcCallAsync(string scriptId, string method, string argsJson, int timeoutMs, CancellationToken cancellationToken)
    {
        if (!_scripts.TryGetValue(scriptId, out var instance))
            throw new InvalidOperationException("scriptId bulunamadi");

        var id = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!instance.PendingRpc.TryAdd(id, tcs))
            throw new InvalidOperationException("rpc kaydi basarisiz");

        var argsPayload = BuildArgsPayload(argsJson);
        var cmd = BuildRpcCommand(id, method, argsPayload);
        await SendCommandAsync(instance, cmd, cancellationToken);

        string line;
        try
        {
            line = await tcs.Task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), cancellationToken);
        }
        catch (Exception ex)
        {
            instance.PendingRpc.TryRemove(id, out _);
            throw new InvalidOperationException($"rpc timeout: {ex.Message}");
        }

        return ParseRpcResponse(line);
    }

    public bool PostMessage(string scriptId, string payloadJson)
    {
        if (!_scripts.TryGetValue(scriptId, out var instance))
            return false;

        var cmd = BuildPostCommand(payloadJson);
        try
        {
            instance.Input.WriteLine(cmd);
            instance.Input.Flush();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Script post hatasi: {ScriptId}", scriptId);
            return false;
        }
    }

    public bool StopScript(string scriptId)
    {
        if (!_scripts.TryRemove(scriptId, out var instance))
            return false;

        try
        {
            instance.Input.WriteLine("{\"op\":\"unload\"}");
            instance.Input.Flush();
        }
        catch
        {
        }

        FinalizeScript(instance);
        return true;
    }

    private Process StartHostProcess(int pid, string scriptId, string scriptPath)
    {
        var hostPath = ResolveHostPath();
        if (string.IsNullOrWhiteSpace(hostPath))
            throw new InvalidOperationException("frida_script_host.py bulunamadi");

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
        psi.ArgumentList.Add("--device");
        psi.ArgumentList.Add(_options.Device);
        if (!string.IsNullOrWhiteSpace(_options.RemoteHost))
        {
            psi.ArgumentList.Add("--remote-host");
            psi.ArgumentList.Add(_options.RemoteHost);
        }
        psi.ArgumentList.Add("--script");
        psi.ArgumentList.Add(scriptPath);
        psi.ArgumentList.Add("--script-id");
        psi.ArgumentList.Add(scriptId);
        psi.ArgumentList.Add("--timeout-ms");
        psi.ArgumentList.Add(_options.TimeoutMs.ToString());

        var process = new Process { StartInfo = psi };
        process.Start();
        return process;
    }

    private async Task ReadOutputAsync(ScriptInstance instance)
    {
        try
        {
            while (!instance.Cancellation.IsCancellationRequested && !instance.Process.HasExited)
            {
                var line = await instance.Process.StandardOutput.ReadLineAsync();
                if (line == null)
                    break;

                if (!TryHandleRpcResponse(instance, line))
                    instance.Events.Enqueue(line);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Script stdout hatasi: {ScriptId}", instance.ScriptId);
        }
    }

    private async Task ReadErrorAsync(ScriptInstance instance)
    {
        try
        {
            while (!instance.Cancellation.IsCancellationRequested && !instance.Process.HasExited)
            {
                var line = await instance.Process.StandardError.ReadLineAsync();
                if (line == null)
                    break;

                instance.Events.Enqueue($"{{\"type\":\"stderr\",\"payload\":\"{Escape(line)}\"}}");
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Script stderr hatasi: {ScriptId}", instance.ScriptId);
        }
    }

    private void OnProcessExit(ScriptInstance instance)
    {
        foreach (var pair in instance.PendingRpc)
            pair.Value.TrySetCanceled();

        instance.IsExited = true;
        instance.ExitCode = instance.Process.HasExited ? instance.Process.ExitCode : -1;
        instance.Events.Enqueue(JsonSerializer.Serialize(new { type = "process_exit", scriptId = instance.ScriptId, pid = instance.Pid, exitCode = instance.ExitCode }));
        instance.Cancellation.Cancel();
        TryDelete(instance.ScriptPath);
    }

    private static void FinalizeScript(ScriptInstance instance)
    {
        instance.Cancellation.Cancel();
        TryKill(instance.Process);
        instance.Cancellation.Dispose();
        TryDelete(instance.ScriptPath);
    }

    private static string BuildArgsPayload(string argsJson)
    {
        if (string.IsNullOrWhiteSpace(argsJson))
            return "[]";

        try
        {
            using var doc = JsonDocument.Parse(argsJson);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
                return doc.RootElement.GetRawText();
        }
        catch (JsonException)
        {
        }

        return "[]";
    }

    private static string BuildRpcCommand(string id, string method, string argsPayload)
    {
        var methodJson = JsonSerializer.Serialize(method);
        return $"{{\"op\":\"rpc\",\"id\":\"{id}\",\"method\":{methodJson},\"args\":{argsPayload}}}";
    }

    private static string BuildPostCommand(string payloadJson)
    {
        var payload = string.IsNullOrWhiteSpace(payloadJson) ? "{}" : payloadJson;
        return $"{{\"op\":\"post\",\"payload\":{payload}}}";
    }

    private static JsonElement ParseRpcResponse(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("rpc yanit gecersiz");

        if (!root.TryGetProperty("ok", out var okElement) || okElement.ValueKind != JsonValueKind.True)
        {
            if (root.TryGetProperty("error", out var errorElement))
                throw new InvalidOperationException(errorElement.GetString() ?? "rpc error");
            throw new InvalidOperationException("rpc error");
        }

        if (root.TryGetProperty("result", out var resultElement))
            return resultElement.Clone();

        return default;
    }

    private bool TryHandleRpcResponse(ScriptInstance instance, string line)
    {
        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return false;

            if (!root.TryGetProperty("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String)
                return false;

            if (!string.Equals(typeElement.GetString(), "rpc_response", StringComparison.OrdinalIgnoreCase))
                return false;

            if (!root.TryGetProperty("id", out var idElement) || idElement.ValueKind != JsonValueKind.String)
                return false;

            var id = idElement.GetString();
            if (string.IsNullOrWhiteSpace(id))
                return false;

            if (instance.PendingRpc.TryRemove(id, out var tcs))
                tcs.TrySetResult(line);

            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private string ResolveHostPath()
    {
        if (!string.IsNullOrWhiteSpace(_options.ScriptHostPath))
            return _options.ScriptHostPath;

        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, "Scripts", "frida_script_host.py");
        if (File.Exists(candidate))
            return candidate;

        var fallback = Path.Combine(baseDir, "frida_script_host.py");
        return File.Exists(fallback) ? fallback : string.Empty;
    }

    private static async Task SendCommandAsync(ScriptInstance instance, string command, CancellationToken cancellationToken)
    {
        await instance.Input.WriteLineAsync(command.AsMemory(), cancellationToken);
        await instance.Input.FlushAsync(cancellationToken);
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

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
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

    private static string Escape(string value)
    {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
}
