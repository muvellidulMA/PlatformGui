using System.Diagnostics;

namespace Mcp.Platform.Gui.Services;

public sealed class ProcessRunner
{
    private readonly object _sync = new();
    private readonly string _name;
    private readonly Action<string, string> _onLog;
    private Process? _process;

    public ProcessRunner(string name, Action<string, string> onLog)
    {
        _name = name;
        _onLog = onLog;
    }

    public event Action<bool>? RunningChanged;

    public bool IsRunning
    {
        get
        {
            lock (_sync)
            {
                return _process != null && !_process.HasExited;
            }
        }
    }

    public bool Start(string fileName, string arguments, string workingDirectory)
    {
        lock (_sync)
        {
            if (_process != null)
                return false;

            var psi = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var process = new Process
            {
                StartInfo = psi,
                EnableRaisingEvents = true
            };

            process.OutputDataReceived += (_, args) =>
            {
                if (!string.IsNullOrWhiteSpace(args.Data))
                    _onLog(_name, args.Data);
            };
            process.ErrorDataReceived += (_, args) =>
            {
                if (!string.IsNullOrWhiteSpace(args.Data))
                    _onLog(_name, args.Data);
            };
            process.Exited += (_, _) =>
            {
                _onLog(_name, "process exited");
                ClearProcess();
            };

            try
            {
                process.Start();
            }
            catch (Exception ex)
            {
                _onLog(_name, $"start error: {ex.Message}");
                process.Dispose();
                return false;
            }

            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            _process = process;
        }

        RunningChanged?.Invoke(true);
        return true;
    }

    public bool Stop()
    {
        Process? process;
        lock (_sync)
        {
            process = _process;
        }

        if (process == null)
            return false;

        try
        {
            if (process.HasExited)
            {
                ClearProcess();
                return true;
            }

            if (!process.HasExited)
                process.Kill(true);
        }
        catch (Exception ex)
        {
            _onLog(_name, $"stop error: {ex.Message}");
            return false;
        }

        return true;
    }

    private void ClearProcess()
    {
        Process? toDispose = null;
        lock (_sync)
        {
            toDispose = _process;
            _process = null;
        }

        try
        {
            toDispose?.Dispose();
        }
        catch
        {
        }

        RunningChanged?.Invoke(false);
    }
}
