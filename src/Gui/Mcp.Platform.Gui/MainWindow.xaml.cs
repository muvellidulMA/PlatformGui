using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using Mcp.Platform.Gui.Models;
using Mcp.Platform.Gui.Services;

namespace Mcp.Platform.Gui;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private readonly ProcessRunner _gatewayRunner;
    private readonly ProcessRunner _workerRunner;
    private readonly ProcessRunner _ngrokRunner;
    private readonly HttpClient _httpClient = new();

    private string _dotnetPath = "dotnet";
    private string _workingDirectory = string.Empty;
    private string _gatewayProjectPath = string.Empty;
    private string _gatewayArgs = string.Empty;
    private string _workerProjectPath = string.Empty;
    private string _workerArgs = string.Empty;
    private string _gatewayUrl = "http://127.0.0.1:13338";
    private string _authToken = "CHANGE_ME";
    private string _ngrokPath = string.Empty;
    private string _ngrokArgs = string.Empty;
    private string _ngrokPort = "13338";
    private bool _gatewayRunning;
    private bool _workerRunning;
    private bool _ngrokRunning;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

        Tools = new ObservableCollection<ToolItem>();
        NgrokTunnels = new ObservableCollection<NgrokTunnelItem>();

        _gatewayRunner = new ProcessRunner("Gateway", AppendLog);
        _workerRunner = new ProcessRunner("Frida", AppendLog);
        _ngrokRunner = new ProcessRunner("Ngrok", AppendLog);

        _gatewayRunner.RunningChanged += isRunning =>
            Dispatcher.Invoke(() => GatewayRunning = isRunning);
        _workerRunner.RunningChanged += isRunning =>
            Dispatcher.Invoke(() => WorkerRunning = isRunning);
        _ngrokRunner.RunningChanged += isRunning =>
            Dispatcher.Invoke(() => NgrokRunning = isRunning);

        var repoRoot = TryFindRepoRoot() ?? Environment.CurrentDirectory;
        WorkingDirectory = repoRoot;
        GatewayProjectPath = Path.Combine(repoRoot, "src", "Gateway", "Mcp.Gateway.App", "Mcp.Gateway.App.csproj");
        WorkerProjectPath = Path.Combine(repoRoot, "src", "Workers", "Frida", "Mcp.Worker.Frida.App", "Mcp.Worker.Frida.App.csproj");
        NgrokPath = Path.Combine(repoRoot, "ngrok", "ngrok.exe");
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<ToolItem> Tools { get; }
    public ObservableCollection<NgrokTunnelItem> NgrokTunnels { get; }

    public string DotnetPath
    {
        get => _dotnetPath;
        set => SetField(ref _dotnetPath, value);
    }

    public string WorkingDirectory
    {
        get => _workingDirectory;
        set => SetField(ref _workingDirectory, value);
    }

    public string GatewayProjectPath
    {
        get => _gatewayProjectPath;
        set => SetField(ref _gatewayProjectPath, value);
    }

    public string GatewayArgs
    {
        get => _gatewayArgs;
        set => SetField(ref _gatewayArgs, value);
    }

    public string WorkerProjectPath
    {
        get => _workerProjectPath;
        set => SetField(ref _workerProjectPath, value);
    }

    public string WorkerArgs
    {
        get => _workerArgs;
        set => SetField(ref _workerArgs, value);
    }

    public string GatewayUrl
    {
        get => _gatewayUrl;
        set => SetField(ref _gatewayUrl, value);
    }

    public string AuthToken
    {
        get => _authToken;
        set => SetField(ref _authToken, value);
    }

    public string NgrokPath
    {
        get => _ngrokPath;
        set => SetField(ref _ngrokPath, value);
    }

    public string NgrokArgs
    {
        get => _ngrokArgs;
        set => SetField(ref _ngrokArgs, value);
    }

    public string NgrokPort
    {
        get => _ngrokPort;
        set => SetField(ref _ngrokPort, value);
    }

    public bool GatewayRunning
    {
        get => _gatewayRunning;
        private set
        {
            if (SetField(ref _gatewayRunning, value))
            {
                OnPropertyChanged(nameof(GatewayCanStart));
                OnPropertyChanged(nameof(GatewayCanStop));
                OnPropertyChanged(nameof(GatewayStatusText));
            }
        }
    }

    public bool WorkerRunning
    {
        get => _workerRunning;
        private set
        {
            if (SetField(ref _workerRunning, value))
            {
                OnPropertyChanged(nameof(WorkerCanStart));
                OnPropertyChanged(nameof(WorkerCanStop));
                OnPropertyChanged(nameof(WorkerStatusText));
            }
        }
    }

    public bool NgrokRunning
    {
        get => _ngrokRunning;
        private set
        {
            if (SetField(ref _ngrokRunning, value))
            {
                OnPropertyChanged(nameof(NgrokCanStart));
                OnPropertyChanged(nameof(NgrokCanStop));
                OnPropertyChanged(nameof(NgrokStatusText));
            }
        }
    }

    public bool GatewayCanStart => !GatewayRunning;
    public bool GatewayCanStop => GatewayRunning;
    public bool WorkerCanStart => !WorkerRunning;
    public bool WorkerCanStop => WorkerRunning;
    public bool NgrokCanStart => !NgrokRunning;
    public bool NgrokCanStop => NgrokRunning;
    public string GatewayStatusText => GatewayRunning ? "Running" : "Stopped";
    public string WorkerStatusText => WorkerRunning ? "Running" : "Stopped";
    public string NgrokStatusText => NgrokRunning ? "Running" : "Stopped";

    private void StartGateway_Click(object sender, RoutedEventArgs e)
    {
        StartProcess(_gatewayRunner, GatewayProjectPath, GatewayArgs);
    }

    private void StopGateway_Click(object sender, RoutedEventArgs e)
    {
        if (!_gatewayRunner.Stop())
            AppendLog("UI", "gateway not running");
    }

    private void StartWorker_Click(object sender, RoutedEventArgs e)
    {
        StartProcess(_workerRunner, WorkerProjectPath, WorkerArgs);
    }

    private void StopWorker_Click(object sender, RoutedEventArgs e)
    {
        if (!_workerRunner.Stop())
            AppendLog("UI", "worker not running");
    }

    private void StartNgrok_Click(object sender, RoutedEventArgs e)
    {
        StartNgrok();
    }

    private void StopNgrok_Click(object sender, RoutedEventArgs e)
    {
        if (!_ngrokRunner.Stop())
            AppendLog("UI", "ngrok not running");
    }

    private async void RefreshTools_Click(object sender, RoutedEventArgs e)
    {
        await RefreshToolsAsync();
    }

    private async void RefreshNgrok_Click(object sender, RoutedEventArgs e)
    {
        await RefreshNgrokAsync();
    }

    private void ClearLog_Click(object sender, RoutedEventArgs e)
    {
        LogTextBox.Clear();
    }

    protected override void OnClosed(EventArgs e)
    {
        _gatewayRunner.Stop();
        _workerRunner.Stop();
        _ngrokRunner.Stop();
        _httpClient.Dispose();
        base.OnClosed(e);
    }

    private void StartProcess(ProcessRunner runner, string projectPath, string extraArgs)
    {
        if (string.IsNullOrWhiteSpace(DotnetPath))
        {
            AppendLog("UI", "dotnet path empty");
            return;
        }

        if (string.IsNullOrWhiteSpace(projectPath))
        {
            AppendLog("UI", "project path empty");
            return;
        }

        var workDir = string.IsNullOrWhiteSpace(WorkingDirectory)
            ? Environment.CurrentDirectory
            : WorkingDirectory;

        var resolvedProject = ResolvePath(projectPath, workDir);
        if (!File.Exists(resolvedProject) && !Directory.Exists(resolvedProject))
        {
            AppendLog("UI", $"project not found: {resolvedProject}");
            return;
        }

        var args = BuildDotnetRunArgs(resolvedProject, extraArgs);
        AppendLog("UI", $"start: {DotnetPath} {args}");

        if (!runner.Start(DotnetPath, args, workDir))
            AppendLog("UI", "already running");
    }

    private void StartNgrok()
    {
        if (string.IsNullOrWhiteSpace(NgrokPath))
        {
            AppendLog("UI", "ngrok path empty");
            return;
        }

        var workDir = string.IsNullOrWhiteSpace(WorkingDirectory)
            ? Environment.CurrentDirectory
            : WorkingDirectory;

        var resolvedPath = ResolvePath(NgrokPath, workDir);
        if (!File.Exists(resolvedPath))
        {
            AppendLog("UI", $"ngrok not found: {resolvedPath}");
            return;
        }

        if (!TryParsePort(NgrokPort, out var port))
        {
            AppendLog("UI", $"invalid port: {NgrokPort}");
            return;
        }

        var args = $"http {port}";
        if (!string.IsNullOrWhiteSpace(NgrokArgs))
            args += $" {NgrokArgs}";

        var ngrokDir = Path.GetDirectoryName(resolvedPath) ?? workDir;
        AppendLog("UI", $"start: {resolvedPath} {args}");

        if (!_ngrokRunner.Start(resolvedPath, args, ngrokDir))
            AppendLog("UI", "ngrok already running");
    }

    private async Task RefreshToolsAsync()
    {
        try
        {
            var baseUrl = (GatewayUrl ?? string.Empty).TrimEnd('/');
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                AppendLog("UI", "gateway url empty");
                return;
            }

            var request = new HttpRequestMessage(HttpMethod.Get, $"{baseUrl}/mcp/tools");
            if (!string.IsNullOrWhiteSpace(AuthToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);

            var response = await _httpClient.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                AppendLog("UI", $"tools error: {(int)response.StatusCode} {response.ReasonPhrase}");
                AppendLog("UI", content);
                return;
            }

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var items = JsonSerializer.Deserialize<List<ToolItem>>(content, options) ?? new List<ToolItem>();

            Dispatcher.Invoke(() =>
            {
                Tools.Clear();
                foreach (var item in items)
                    Tools.Add(item);
            });
        }
        catch (Exception ex)
        {
            AppendLog("UI", $"tools exception: {ex.Message}");
        }
    }

    private async Task RefreshNgrokAsync()
    {
        try
        {
            var response = await _httpClient.GetAsync("http://127.0.0.1:4040/api/tunnels");
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                AppendLog("UI", $"ngrok api error: {(int)response.StatusCode} {response.ReasonPhrase}");
                AppendLog("UI", content);
                return;
            }

            var list = ParseNgrokTunnels(content);
            Dispatcher.Invoke(() =>
            {
                NgrokTunnels.Clear();
                foreach (var item in list)
                    NgrokTunnels.Add(item);
            });
        }
        catch (Exception ex)
        {
            AppendLog("UI", $"ngrok api exception: {ex.Message}");
        }
    }

    private static string BuildDotnetRunArgs(string projectPath, string extraArgs)
    {
        var args = $"run --project {Quote(projectPath)}";
        if (!string.IsNullOrWhiteSpace(extraArgs))
            args += $" -- {extraArgs}";
        return args;
    }

    private static string ResolvePath(string path, string baseDir)
    {
        if (Path.IsPathRooted(path))
            return path;

        return Path.GetFullPath(Path.Combine(baseDir, path));
    }

    private static string Quote(string value)
    {
        return value.Contains(' ') ? $"\"{value}\"" : value;
    }

    private static bool TryParsePort(string text, out int port)
    {
        port = 0;
        if (!int.TryParse(text, out port))
            return false;

        return port > 0 && port <= 65535;
    }

    private static string? TryFindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "McpPlatform.sln");
            if (File.Exists(candidate))
                return dir.FullName;

            dir = dir.Parent;
        }

        return null;
    }

    private static List<NgrokTunnelItem> ParseNgrokTunnels(string json)
    {
        var list = new List<NgrokTunnelItem>();
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("tunnels", out var tunnels) || tunnels.ValueKind != JsonValueKind.Array)
            return list;

        foreach (var item in tunnels.EnumerateArray())
        {
            var name = item.TryGetProperty("name", out var nameElement) ? nameElement.GetString() ?? string.Empty : string.Empty;
            var publicUrl = item.TryGetProperty("public_url", out var urlElement) ? urlElement.GetString() ?? string.Empty : string.Empty;
            var proto = item.TryGetProperty("proto", out var protoElement) ? protoElement.GetString() ?? string.Empty : string.Empty;
            var addr = string.Empty;
            if (item.TryGetProperty("config", out var config) && config.ValueKind == JsonValueKind.Object)
                addr = config.TryGetProperty("addr", out var addrElement) ? addrElement.GetString() ?? string.Empty : string.Empty;

            list.Add(new NgrokTunnelItem(name, publicUrl, proto, addr));
        }

        return list;
    }

    private void AppendLog(string source, string message)
    {
        Dispatcher.Invoke(() =>
        {
            LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {source}: {message}\r\n");
            LogTextBox.ScrollToEnd();
        });
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;

        field = value;
        OnPropertyChanged(name);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
