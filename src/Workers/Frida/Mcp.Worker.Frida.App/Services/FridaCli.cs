using System.Diagnostics;
using System.Text.Json;
using Mcp.Worker.Frida.App.Models;
using Mcp.Worker.Frida.App.Options;

namespace Mcp.Worker.Frida.App.Services;

public sealed class FridaCli
{
    private readonly FridaOptions _options;
    private readonly ILogger<FridaCli> _logger;

    public FridaCli(FridaOptions options, ILogger<FridaCli> logger)
    {
        _options = options;
        _logger = logger;
    }

    public async Task<IReadOnlyList<FridaProcessInfo>> ListProcessesAsync(CancellationToken cancellationToken)
    {
        var result = await RunFridaPsAsync(useJson: _options.UseJson, cancellationToken);
        if (result.ExitCode == 0 && LooksLikeJson(result.Stdout))
        {
            try
            {
                return ParseJsonProcesses(result.Stdout);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Frida JSON parse hatasi");
            }
        }

        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.Stdout))
        {
            var fallback = await RunFridaPsAsync(useJson: false, cancellationToken);
            if (fallback.ExitCode == 0 && !string.IsNullOrWhiteSpace(fallback.Stdout))
                return ParseTextProcesses(fallback.Stdout);

            var error = string.IsNullOrWhiteSpace(fallback.Stderr) ? "frida-ps calismadi" : fallback.Stderr.Trim();
            throw new InvalidOperationException(error);
        }

        return ParseTextProcesses(result.Stdout);
    }

    public async Task<JsonElement> AttachAsync(int pid, CancellationToken cancellationToken)
        => await RunHelperAsync("attach", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString()
        }, cancellationToken);

    public async Task<JsonElement> ListModulesAsync(int pid, CancellationToken cancellationToken)
        => await RunHelperAsync("list_modules", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString()
        }, cancellationToken);

    public async Task<JsonElement> ListExportsAsync(int pid, string moduleName, CancellationToken cancellationToken)
        => await RunHelperAsync("list_exports", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString(),
            ["module"] = moduleName
        }, cancellationToken);

    public async Task<JsonElement> ReadMemoryAsync(int pid, string address, int size, CancellationToken cancellationToken)
        => await RunHelperAsync("read_memory", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString(),
            ["address"] = address,
            ["size"] = size.ToString()
        }, cancellationToken);

    public async Task<JsonElement> ReadStringAsync(int pid, string address, int maxLength, string encoding, CancellationToken cancellationToken)
        => await RunHelperAsync("read_string", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString(),
            ["address"] = address,
            ["max-length"] = maxLength.ToString(),
            ["encoding"] = encoding
        }, cancellationToken);

    public async Task<JsonElement> ScanMemoryAsync(int pid, string address, int size, string pattern, CancellationToken cancellationToken)
        => await RunHelperAsync("scan_memory", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString(),
            ["address"] = address,
            ["size"] = size.ToString(),
            ["pattern"] = pattern
        }, cancellationToken);

    public async Task<JsonElement> WriteMemoryAsync(int pid, string address, string dataHex, CancellationToken cancellationToken)
        => await RunHelperAsync("write_memory", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString(),
            ["address"] = address,
            ["data-hex"] = dataHex
        }, cancellationToken);

    public async Task<JsonElement> CallFunctionAsync(
        int pid,
        string address,
        string returnType,
        string argTypesJson,
        string argValuesJson,
        CancellationToken cancellationToken)
        => await RunHelperAsync("call_function", new Dictionary<string, string>
        {
            ["pid"] = pid.ToString(),
            ["address"] = address,
            ["ret-type"] = returnType,
            ["arg-types"] = argTypesJson,
            ["arg-values"] = argValuesJson
        }, cancellationToken);

    private async Task<ExecResult> RunFridaPsAsync(bool useJson, CancellationToken cancellationToken)
    {
        var args = BuildFridaPsArgs(useJson);
        return await RunProcessAsync(_options.FridaPsPath, args, _options.TimeoutMs, cancellationToken);
    }

    private async Task<JsonElement> RunHelperAsync(string op, Dictionary<string, string> args, CancellationToken cancellationToken)
    {
        var helperPath = ResolveHelperPath();
        if (string.IsNullOrWhiteSpace(helperPath))
            throw new InvalidOperationException("frida_helper.py bulunamadi");

        var cmdArgs = new List<string>();
        if (_options.PythonArgs.Length > 0)
            cmdArgs.AddRange(_options.PythonArgs);

        cmdArgs.Add(helperPath);
        cmdArgs.Add("--op");
        cmdArgs.Add(op);
        cmdArgs.Add("--device");
        cmdArgs.Add(_options.Device);

        if (!string.IsNullOrWhiteSpace(_options.RemoteHost))
        {
            cmdArgs.Add("--remote-host");
            cmdArgs.Add(_options.RemoteHost);
        }

        cmdArgs.Add("--timeout-ms");
        cmdArgs.Add(_options.TimeoutMs.ToString());

        foreach (var pair in args)
        {
            cmdArgs.Add($"--{pair.Key}");
            cmdArgs.Add(pair.Value);
        }

        var result = await RunProcessAsync(_options.PythonPath, cmdArgs, _options.TimeoutMs + 2000, cancellationToken);
        if (result.ExitCode != 0 && string.IsNullOrWhiteSpace(result.Stdout))
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Stderr) ? "frida helper hatasi" : result.Stderr.Trim());

        var json = result.Stdout.Trim();
        if (string.IsNullOrWhiteSpace(json))
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.Stderr) ? "frida helper bos cikti" : result.Stderr.Trim());

        return ParseHelperResult(json);
    }

    private JsonElement ParseHelperResult(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("helper json gecersiz");

        var root = doc.RootElement;
        if (!root.TryGetProperty("ok", out var okElement) || okElement.ValueKind != JsonValueKind.True)
        {
            if (root.TryGetProperty("error", out var errorElement))
                throw new InvalidOperationException(errorElement.GetString() ?? "helper error");
            throw new InvalidOperationException("helper error");
        }

        if (root.TryGetProperty("data", out var dataElement))
            return dataElement.Clone();

        return default;
    }

    private string ResolveHelperPath()
    {
        if (!string.IsNullOrWhiteSpace(_options.HelperScriptPath))
            return _options.HelperScriptPath;

        var baseDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(baseDir, "Scripts", "frida_helper.py");
        if (File.Exists(candidate))
            return candidate;

        var fallback = Path.Combine(baseDir, "frida_helper.py");
        return File.Exists(fallback) ? fallback : string.Empty;
    }

    private List<string> BuildFridaPsArgs(bool useJson)
    {
        var args = new List<string>();
        if (useJson)
            args.Add("-j");

        AddListModeArgs(args);
        AddDeviceArgs(args);
        return args;
    }

    private void AddListModeArgs(List<string> args)
    {
        var mode = _options.ListMode?.Trim().ToLowerInvariant() ?? string.Empty;
        switch (mode)
        {
            case "apps":
                args.Add("-a");
                break;
            case "all":
                break;
            case "default":
            case "":
                break;
        }
    }

    private void AddDeviceArgs(List<string> args)
    {
        var device = _options.Device?.Trim().ToLowerInvariant();
        switch (device)
        {
            case "usb":
                args.Add("-U");
                break;
            case "remote":
                args.Add("-R");
                break;
            case "host":
                if (!string.IsNullOrWhiteSpace(_options.RemoteHost))
                {
                    args.Add("-H");
                    args.Add(_options.RemoteHost);
                }
                break;
            case "local":
            default:
                break;
        }
    }

    private async Task<ExecResult> RunProcessAsync(
        string fileName,
        IEnumerable<string> args,
        int timeoutMs,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = new Process { StartInfo = psi };
        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            return ExecResult.FromException(ex);
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        var waitTask = process.WaitForExitAsync(cancellationToken);

        var completed = await Task.WhenAny(waitTask, Task.Delay(timeoutMs, cancellationToken));
        if (completed != waitTask)
        {
            TryKill(process);
            return new ExecResult(-1, await stdoutTask, await stderrTask, true);
        }

        try
        {
            await waitTask;
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }

        return new ExecResult(process.ExitCode, await stdoutTask, await stderrTask, false);
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

    private static bool LooksLikeJson(string text)
        => text.TrimStart().StartsWith("[", StringComparison.Ordinal) ||
           text.TrimStart().StartsWith("{", StringComparison.Ordinal);

    private static IReadOnlyList<FridaProcessInfo> ParseJsonProcesses(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind == JsonValueKind.Array)
            return ParseProcessArray(doc.RootElement);

        if (doc.RootElement.ValueKind == JsonValueKind.Object &&
            doc.RootElement.TryGetProperty("processes", out var processesElement) &&
            processesElement.ValueKind == JsonValueKind.Array)
            return ParseProcessArray(processesElement);

        return Array.Empty<FridaProcessInfo>();
    }

    private static IReadOnlyList<FridaProcessInfo> ParseProcessArray(JsonElement array)
    {
        var list = new List<FridaProcessInfo>();
        foreach (var item in array.EnumerateArray())
        {
            if (!item.TryGetProperty("pid", out var pidElement) || !pidElement.TryGetInt32(out var pid))
                continue;

            var name = item.TryGetProperty("name", out var nameElement)
                ? nameElement.GetString() ?? string.Empty
                : string.Empty;

            list.Add(new FridaProcessInfo(pid, name));
        }

        return list;
    }

    private static IReadOnlyList<FridaProcessInfo> ParseTextProcesses(string text)
    {
        var list = new List<FridaProcessInfo>();
        var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var rawLine in lines)
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
                continue;

            if (line.StartsWith("PID", StringComparison.OrdinalIgnoreCase))
                continue;

            if (line.StartsWith("-", StringComparison.Ordinal))
                continue;

            var pidText = ReadLeadingNumber(line, out var index);
            if (pidText == null || !int.TryParse(pidText, out var pid))
                continue;

            var name = line.Substring(index).Trim();
            list.Add(new FridaProcessInfo(pid, name));
        }

        return list;
    }

    private static string? ReadLeadingNumber(string line, out int index)
    {
        index = 0;
        while (index < line.Length && char.IsWhiteSpace(line[index]))
            index++;

        var start = index;
        while (index < line.Length && char.IsDigit(line[index]))
            index++;

        if (index == start)
            return null;

        return line.Substring(start, index - start);
    }

    private sealed record ExecResult(int ExitCode, string Stdout, string Stderr, bool TimedOut)
    {
        public static ExecResult FromException(Exception ex) => new(-1, string.Empty, ex.Message, false);
    }
}
