using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using Mcp.Worker.Frida.App.Options;

namespace Mcp.Worker.Frida.App.Services;

public sealed class FridaHookManager
{
    private sealed class HookInstance
    {
        public HookInstance(string hookId, int pid, Process process, string scriptPath, bool autoStopOnFirstEvent)
        {
            HookId = hookId;
            Pid = pid;
            Process = process;
            ScriptPath = scriptPath;
            AutoStopOnFirstEvent = autoStopOnFirstEvent;
        }

        public string HookId { get; }
        public int Pid { get; }
        public Process Process { get; }
        public string ScriptPath { get; }
        public bool AutoStopOnFirstEvent { get; }
        public ConcurrentQueue<string> Events { get; } = new();
        public CancellationTokenSource Cancellation { get; } = new();
    }

    private readonly ConcurrentDictionary<string, HookInstance> _hooks = new(StringComparer.OrdinalIgnoreCase);
    private readonly FridaOptions _options;
    private readonly ILogger<FridaHookManager> _logger;

    public FridaHookManager(FridaOptions options, ILogger<FridaHookManager> logger)
    {
        _options = options;
        _logger = logger;
    }

    public string StartHook(int pid, string scriptSource, bool autoStopOnFirstEvent = false)
    {
        var hookId = Guid.NewGuid().ToString("N");
        var scriptPath = Path.Combine(Path.GetTempPath(), $"frida_hook_{hookId}.js");
        File.WriteAllText(scriptPath, scriptSource, new UTF8Encoding(false));

        var process = StartHookerProcess(pid, scriptPath);
        var hook = new HookInstance(hookId, pid, process, scriptPath, autoStopOnFirstEvent);
        _hooks[hookId] = hook;

        _ = Task.Run(() => ReadOutputAsync(hook));
        _ = Task.Run(() => ReadErrorAsync(hook));

        return hookId;
    }

    public IReadOnlyList<string> PollEvents(string hookId, int maxEvents)
    {
        if (!_hooks.TryGetValue(hookId, out var hook))
            return Array.Empty<string>();

        var list = new List<string>(Math.Max(1, maxEvents));
        for (var i = 0; i < maxEvents; i++)
        {
            if (!hook.Events.TryDequeue(out var evt))
                break;

            list.Add(evt);
        }

        if (hook.AutoStopOnFirstEvent && list.Count > 0)
            StopHook(hookId);

        return list;
    }

    public bool StopHook(string hookId)
    {
        if (!_hooks.TryRemove(hookId, out var hook))
            return false;

        hook.Cancellation.Cancel();
        TryKill(hook.Process);
        hook.Cancellation.Dispose();
        TryDelete(hook.ScriptPath);
        return true;
    }

    private Process StartHookerProcess(int pid, string scriptPath)
    {
        var hookerPath = ResolveHookerPath();
        if (string.IsNullOrWhiteSpace(hookerPath))
            throw new InvalidOperationException("frida_hooker.py bulunamadi");

        var psi = new ProcessStartInfo
        {
            FileName = _options.PythonPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var arg in _options.PythonArgs)
            psi.ArgumentList.Add(arg);

        psi.ArgumentList.Add(hookerPath);
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
        psi.ArgumentList.Add("--timeout-ms");
        psi.ArgumentList.Add(_options.TimeoutMs.ToString());

        var process = new Process { StartInfo = psi };
        process.Start();
        return process;
    }

    private async Task ReadOutputAsync(HookInstance hook)
    {
        try
        {
            while (!hook.Cancellation.IsCancellationRequested && !hook.Process.HasExited)
            {
                var line = await hook.Process.StandardOutput.ReadLineAsync();
                if (line == null)
                    break;

                hook.Events.Enqueue(line);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Hook stdout okuma hatasi: {HookId}", hook.HookId);
        }
    }

    private async Task ReadErrorAsync(HookInstance hook)
    {
        try
        {
            while (!hook.Cancellation.IsCancellationRequested && !hook.Process.HasExited)
            {
                var line = await hook.Process.StandardError.ReadLineAsync();
                if (line == null)
                    break;

                hook.Events.Enqueue($"{{\"type\":\"stderr\",\"payload\":\"{Escape(line)}\"}}");
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Hook stderr okuma hatasi: {HookId}", hook.HookId);
        }
    }

    private string ResolveHookerPath()
    {
        if (!string.IsNullOrWhiteSpace(_options.HookerScriptPath))
            return _options.HookerScriptPath;

        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, "Scripts", "frida_hooker.py");
        if (File.Exists(candidate))
            return candidate;

        var fallback = Path.Combine(baseDir, "frida_hooker.py");
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

    private static string Escape(string value)
    {
        return value.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
}
