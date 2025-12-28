using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Text;
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
    private CancellationTokenSource? _sseCts;
    private Task? _sseTask;

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
    private ToolItem? _selectedTool;
    private string _selectedToolDescription = string.Empty;
    private string _invokeToolName = string.Empty;
    private string _invokeArgsJson = "{}";
    private string _invokeResult = string.Empty;
    private string _sseUrl = "http://127.0.0.1:13338/sse";
    private string _sseToken = "CHANGE_ME";
    private bool _gatewayRunning;
    private bool _workerRunning;
    private bool _ngrokRunning;
    private bool _sseRunning;

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
        SseUrl = BuildSseUrl(GatewayUrl);
        SseToken = AuthToken;
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

    public ToolItem? SelectedTool
    {
        get => _selectedTool;
        set
        {
            if (SetField(ref _selectedTool, value))
            {
                SelectedToolDescription = value?.Description ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(value?.Name))
                    InvokeToolName = value.Name;
            }
        }
    }

    public string SelectedToolDescription
    {
        get => _selectedToolDescription;
        private set => SetField(ref _selectedToolDescription, value);
    }

    public string InvokeToolName
    {
        get => _invokeToolName;
        set => SetField(ref _invokeToolName, value);
    }

    public string InvokeArgsJson
    {
        get => _invokeArgsJson;
        set => SetField(ref _invokeArgsJson, value);
    }

    public string InvokeResult
    {
        get => _invokeResult;
        private set => SetField(ref _invokeResult, value);
    }

    public string SseUrl
    {
        get => _sseUrl;
        set => SetField(ref _sseUrl, value);
    }

    public string SseToken
    {
        get => _sseToken;
        set => SetField(ref _sseToken, value);
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

    public bool SseRunning
    {
        get => _sseRunning;
        private set
        {
            if (SetField(ref _sseRunning, value))
            {
                OnPropertyChanged(nameof(SseCanStart));
                OnPropertyChanged(nameof(SseCanStop));
                OnPropertyChanged(nameof(SseStatusText));
            }
        }
    }

    public bool GatewayCanStart => !GatewayRunning;
    public bool GatewayCanStop => GatewayRunning;
    public bool WorkerCanStart => !WorkerRunning;
    public bool WorkerCanStop => WorkerRunning;
    public bool NgrokCanStart => !NgrokRunning;
    public bool NgrokCanStop => NgrokRunning;
    public bool SseCanStart => !SseRunning;
    public bool SseCanStop => SseRunning;
    public string GatewayStatusText => GatewayRunning ? "Running" : "Stopped";
    public string WorkerStatusText => WorkerRunning ? "Running" : "Stopped";
    public string NgrokStatusText => NgrokRunning ? "Running" : "Stopped";
    public string SseStatusText => SseRunning ? "Running" : "Stopped";

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

    private async void InvokeTool_Click(object sender, RoutedEventArgs e)
    {
        await InvokeToolAsync();
    }

    private void ClearInvoke_Click(object sender, RoutedEventArgs e)
    {
        InvokeResult = string.Empty;
    }

    private void StartSse_Click(object sender, RoutedEventArgs e)
    {
        StartSse();
    }

    private void StopSse_Click(object sender, RoutedEventArgs e)
    {
        StopSse();
    }

    private void ClearSse_Click(object sender, RoutedEventArgs e)
    {
        SseTextBox.Clear();
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
        StopSse();
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

    private async Task InvokeToolAsync()
    {
        try
        {
            var baseUrl = (GatewayUrl ?? string.Empty).TrimEnd('/');
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                AppendLog("UI", "gateway url empty");
                return;
            }

            var toolName = (InvokeToolName ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(toolName))
            {
                AppendLog("UI", "tool name empty");
                return;
            }

            var argsJson = string.IsNullOrWhiteSpace(InvokeArgsJson) ? "{}" : InvokeArgsJson;
            var payload = JsonSerializer.Serialize(new { name = toolName, argsJson });
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/mcp/invoke");
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            if (!string.IsNullOrWhiteSpace(AuthToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);

            var response = await _httpClient.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                AppendLog("UI", $"invoke error: {(int)response.StatusCode} {response.ReasonPhrase}");
                InvokeResult = FormatInvokeResult(content);
                return;
            }

            InvokeResult = FormatInvokeResult(content);
        }
        catch (Exception ex)
        {
            AppendLog("UI", $"invoke exception: {ex.Message}");
            InvokeResult = ex.Message;
        }
    }

    private void StartSse()
    {
        if (SseRunning)
            return;

        if (string.IsNullOrWhiteSpace(SseUrl))
        {
            AppendLog("UI", "sse url empty");
            return;
        }

        _sseCts = new CancellationTokenSource();
        SseRunning = true;
        _sseTask = Task.Run(() => RunSseAsync(_sseCts.Token));
    }

    private void StopSse()
    {
        if (!SseRunning)
            return;

        _sseCts?.Cancel();
        _sseCts?.Dispose();
        _sseCts = null;
    }

    private async Task RunSseAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, SseUrl);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            if (!string.IsNullOrWhiteSpace(SseToken))
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", SseToken);

            using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                AppendSseLog($"error: {(int)response.StatusCode} {response.ReasonPhrase}");
                return;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var reader = new StreamReader(stream);
            var eventName = string.Empty;
            var dataBuilder = new StringBuilder();

            while (!cancellationToken.IsCancellationRequested && !reader.EndOfStream)
            {
                var line = await reader.ReadLineAsync();
                if (line == null)
                    break;

                if (line.Length == 0)
                {
                    EmitSseEvent(eventName, dataBuilder.ToString());
                    eventName = string.Empty;
                    dataBuilder.Clear();
                    continue;
                }

                if (line.StartsWith("event:", StringComparison.OrdinalIgnoreCase))
                {
                    eventName = line.Substring(6).Trim();
                    continue;
                }

                if (line.StartsWith("data:", StringComparison.OrdinalIgnoreCase))
                {
                    dataBuilder.AppendLine(line.Substring(5).Trim());
                }
            }
        }
        catch (OperationCanceledException)
        {
            AppendSseLog("stopped");
        }
        catch (Exception ex)
        {
            AppendSseLog($"error: {ex.Message}");
        }
        finally
        {
            Dispatcher.Invoke(() => SseRunning = false);
        }
    }

    private void EmitSseEvent(string eventName, string data)
    {
        if (string.IsNullOrWhiteSpace(data))
            return;

        var name = string.IsNullOrWhiteSpace(eventName) ? "message" : eventName;
        AppendSseLog($"{name}: {data.TrimEnd()}");
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

    private static string BuildSseUrl(string baseUrl)
    {
        var trimmed = (baseUrl ?? string.Empty).TrimEnd('/');
        if (string.IsNullOrWhiteSpace(trimmed))
            return "http://127.0.0.1:13338/sse";

        return $"{trimmed}/sse";
    }

    private static string FormatInvokeResult(string content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return string.Empty;

        try
        {
            using var doc = JsonDocument.Parse(content);
            if (TryExtractTextPayload(doc.RootElement, out var textPayload))
            {
                if (TryFormatJson(textPayload, out var formatted))
                    return formatted;

                return textPayload;
            }

            return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException)
        {
            return content;
        }
    }

    private static bool TryExtractTextPayload(JsonElement root, out string payload)
    {
        payload = string.Empty;
        if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() == 0)
            return false;

        var first = root[0];
        if (first.ValueKind != JsonValueKind.Object)
            return false;

        if (!first.TryGetProperty("text", out var textElement) || textElement.ValueKind != JsonValueKind.String)
            return false;

        payload = textElement.GetString() ?? string.Empty;
        return payload.Length > 0;
    }

    private static bool TryFormatJson(string text, out string formatted)
    {
        formatted = string.Empty;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(text);
            formatted = JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
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

    private void AppendSseLog(string message)
    {
        Dispatcher.Invoke(() =>
        {
            SseTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\r\n");
            SseTextBox.ScrollToEnd();
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
