using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace Mcp.Platform.Gui;

public partial class App : Application
{
    private const string LogFileName = "mcp-gui-crash.log";

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        base.OnStartup(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        LogException(e.Exception, "dispatcher");
        ShowCrashMessage(e.Exception);
        e.Handled = true;
        Shutdown();
    }

    private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            LogException(ex, "domain");
            ShowCrashMessage(ex);
        }
        else
        {
            LogText("domain", e.ExceptionObject?.ToString() ?? "unknown error");
            MessageBox.Show("Uygulama hata verdi. Log dosyasini kontrol edin.", "MCP GUI", MessageBoxButton.OK, MessageBoxImage.Error);
        }

        Shutdown();
    }

    private static void LogException(Exception ex, string source)
    {
        var message = $"{DateTime.Now:O} [{source}] {ex}\r\n";
        File.AppendAllText(GetLogPath(), message);
    }

    private static void LogText(string source, string message)
    {
        var line = $"{DateTime.Now:O} [{source}] {message}\r\n";
        File.AppendAllText(GetLogPath(), line);
    }

    private static string GetLogPath()
    {
        var dir = Path.GetTempPath();
        return Path.Combine(dir, LogFileName);
    }

    private static void ShowCrashMessage(Exception ex)
    {
        var path = GetLogPath();
        MessageBox.Show($"Uygulama hata verdi. Log: {path}\n\n{ex.Message}", "MCP GUI", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
