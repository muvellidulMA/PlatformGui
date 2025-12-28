namespace Mcp.Worker.Frida.App.Options;

public sealed class FridaOptions
{
    public int Port { get; set; } = 5052;
    public string FridaPsPath { get; set; } = "frida-ps";
    public string FridaPath { get; set; } = "frida";
    public string Device { get; set; } = "local";
    public string? RemoteHost { get; set; }
    public int TimeoutMs { get; set; } = 5000;
    public bool UseJson { get; set; } = true;
    public string? ReadMemoryScriptPath { get; set; }
    public string ListMode { get; set; } = "all";
    public string PythonPath { get; set; } = "python";
    public string[] PythonArgs { get; set; } = Array.Empty<string>();
    public string? HelperScriptPath { get; set; }
    public string? HookerScriptPath { get; set; }
    public string? ScriptHostPath { get; set; }
    public string[] BlockedTools { get; set; } = Array.Empty<string>();
}
