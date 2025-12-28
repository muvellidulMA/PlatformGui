using Grpc.Core;
using Mcp.Worker.Frida.App.Options;
using Mcp.Workers.Protocol;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
namespace Mcp.Worker.Frida.App.Services
{
    public sealed class FridaWorkerService : global::Mcp.Workers.Protocol.Worker.WorkerBase
    {
        private const string ToolListProcesses = "list_processes";
        private const string ToolAttach = "attach";
        private const string ToolListModules = "list_modules";
        private const string ToolListExports = "list_exports";
        private const string ToolReadMemory = "read_memory";
        private const string ToolReadString = "read_string";
        private const string ToolScanMemory = "scan_memory";
        private const string ToolWriteMemory = "write_memory";
        private const string ToolCallFunction = "call_function";
        private const string ToolSpawn = "spawn";
        private const string ToolResume = "resume";
        private const string ToolKill = "kill";
        private const string ToolHookStart = "hook_start";
        private const string ToolHookPoll = "hook_poll";
        private const string ToolHookStop = "hook_stop";
        private const string ToolSetBreakpoint = "set_breakpoint";
        private const string ToolScriptLoad = "script_load";
        private const string ToolScriptUnload = "script_unload";
        private const string ToolScriptMessagePoll = "script_message_poll";
        private const string ToolRpcCall = "rpc_call";
        private const string ToolScriptPost = "script_post";
        private const string ToolTestStrings = "test_strings";

        private readonly FridaCli _cli;
        private readonly FridaSessionStore _sessions;
        private readonly FridaOptions _options;
        private readonly FridaHookManager _hookManager;
        private readonly FridaScriptManager _scriptManager;
        private readonly FridaToolPolicy _policy;
        private readonly ILogger<FridaWorkerService> _logger;

        public FridaWorkerService(
            FridaCli cli,
            FridaSessionStore sessions,
            FridaOptions options,
            FridaHookManager hookManager,
            FridaScriptManager scriptManager,
            FridaToolPolicy policy,
            ILogger<FridaWorkerService> logger)
        {
            _cli = cli;
            _sessions = sessions;
            _options = options;
            _hookManager = hookManager;
            _scriptManager = scriptManager;
            _policy = policy;
            _logger = logger;
        }

        public override Task<ListToolsReply> ListTools(ListToolsRequest request, ServerCallContext context)
            => Task.FromResult(new ListToolsReply
            {
                Tools =
                {
                    new ToolInfo
                    {
                        Name = ToolListProcesses,
                        Description = "Proses listesi. Gerekli: yok. Cikti: [{Pid,Name}].",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": {}, ""additionalProperties"": false }"
                    },
                    new ToolInfo
                    {
                        Name = ToolAttach,
                        Description = "Proses attach. Gerekli: pid. Cikti: sessionId.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolListModules,
                        Description = "Modul listesi. Gerekli: pid veya sessionId.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolListExports,
                        Description = "Modul export listesi. Gerekli: pid veya sessionId, module.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" } }, ""required"": [""module""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolReadMemory,
                        Description = "Bellekten hex okur. Gerekli: pid veya sessionId, address, size.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""size"": { ""type"": ""integer"" } }, ""required"": [""address"", ""size""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolReadString,
                        Description = "Bellekten string okur. Gerekli: pid veya sessionId, address. Opsiyonel: maxLength, encoding.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""maxLength"": { ""type"": ""integer"" }, ""encoding"": { ""type"": ""string"" } }, ""required"": [""address""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScanMemory,
                        Description = "Bellek tarama. Gerekli: pid veya sessionId, address, size, pattern.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""size"": { ""type"": ""integer"" }, ""pattern"": { ""type"": ""string"" } }, ""required"": [""address"", ""size"", ""pattern""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolWriteMemory,
                        Description = "Bellege hex yazar. Gerekli: pid veya sessionId, address, dataHex.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""dataHex"": { ""type"": ""string"" } }, ""required"": [""address"", ""dataHex""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolCallFunction,
                        Description = "Adresteki fonksiyonu cagirir. Gerekli: pid veya sessionId, address, argTypes, argValues. Opsiyonel: returnType.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""returnType"": { ""type"": ""string"" }, ""argTypes"": { ""type"": ""array"", ""items"": { ""type"": ""string"" } }, ""argValues"": { ""type"": ""array"", ""items"": {} } }, ""required"": [""address"", ""argTypes"", ""argValues""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolSpawn,
                        Description = "Proses spawn (suspended). Gerekli: program (veya path). Opsiyonel: args.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""program"": { ""type"": ""string"" }, ""path"": { ""type"": ""string"" }, ""args"": { ""type"": ""array"", ""items"": { ""type"": ""string"" } } }, ""required"": [""program""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolResume,
                        Description = "Spawn edilen prosesi devam ettirir. Gerekli: pid.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolKill,
                        Description = "Proses sonlandirir. Gerekli: pid.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookStart,
                        Description = "Hook baslatir. Gerekli: pid veya sessionId, address veya module+export. Opsiyonel: includeArgs, includeRetval, includeBacktrace, maxArgs, once, autoStop, stream, pollIntervalMs, maxEvents.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" }, ""export"": { ""type"": ""string"" }, ""maxArgs"": { ""type"": ""integer"" }, ""includeArgs"": { ""type"": ""boolean"" }, ""includeBacktrace"": { ""type"": ""boolean"" }, ""includeRetval"": { ""type"": ""boolean"" }, ""once"": { ""type"": ""boolean"" }, ""autoStop"": { ""type"": ""boolean"" }, ""stream"": { ""type"": ""boolean"" }, ""pollIntervalMs"": { ""type"": ""integer"" }, ""maxEvents"": { ""type"": ""integer"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookPoll,
                        Description = "Hook event okur. Gerekli: hookId. Opsiyonel: maxEvents.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""hookId"": { ""type"": ""string"" }, ""maxEvents"": { ""type"": ""integer"" } }, ""required"": [""hookId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookStop,
                        Description = "Hook durdurur. Gerekli: hookId.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""hookId"": { ""type"": ""string"" } }, ""required"": [""hookId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolSetBreakpoint,
                        Description = "Breakpoint (hook tabanli). Gerekli: pid veya sessionId, address veya module+export. Opsiyonel: includeArgs, includeRetval, includeBacktrace, maxArgs, once, autoStop, stream, pollIntervalMs, maxEvents.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" }, ""export"": { ""type"": ""string"" }, ""maxArgs"": { ""type"": ""integer"" }, ""includeArgs"": { ""type"": ""boolean"" }, ""includeBacktrace"": { ""type"": ""boolean"" }, ""once"": { ""type"": ""boolean"" }, ""stream"": { ""type"": ""boolean"" }, ""pollIntervalMs"": { ""type"": ""integer"" }, ""maxEvents"": { ""type"": ""integer"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptLoad,
                        Description = "Script inject eder. Gerekli: pid veya sessionId, source.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""source"": { ""type"": ""string"" } }, ""required"": [""source""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptUnload,
                        Description = "Script kaldirir. Gerekli: scriptId.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" } }, ""required"": [""scriptId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptMessagePoll,
                        Description = "Script mesajlarini okur. Gerekli: scriptId. Opsiyonel: maxEvents.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" }, ""maxEvents"": { ""type"": ""integer"" } }, ""required"": [""scriptId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolRpcCall,
                        Description = "rpc.exports method cagirir. Gerekli: scriptId, method. Opsiyonel: args, timeoutMs.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" }, ""method"": { ""type"": ""string"" }, ""args"": { ""type"": ""array"", ""items"": {} }, ""timeoutMs"": { ""type"": ""integer"" } }, ""required"": [""scriptId"", ""method""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptPost,
                        Description = "Script recv icin payload gonderir. Gerekli: scriptId, payload.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" }, ""payload"": { ""type"": [""object"", ""array"", ""string"", ""number"", ""boolean""] } }, ""required"": [""scriptId"", ""payload""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolTestStrings,
                        Description = "Test string allocate eder. Gerekli: pid veya sessionId. Opsiyonel: asciiText, utf16Text, timeoutMs.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""asciiText"": { ""type"": ""string"" }, ""utf16Text"": { ""type"": ""string"" }, ""timeoutMs"": { ""type"": ""integer"" } } }"
                    }
                }
            });

        public override async Task<InvokeToolReply> InvokeTool(InvokeToolRequest request, ServerCallContext context)
        {
            try
            {
                var decision = _policy.Evaluate(request.Name, request.ArgsJson);
                _logger.LogInformation("Tool policy: {Tool} allowed={Allowed} risk={Risk} {Detail}", request.Name, decision.Allowed, decision.Risk, decision.Detail);
                if (!decision.Allowed)
                    return new InvokeToolReply { Error = $"policy denied: {decision.Detail}" };

                switch (request.Name)
                {
                    case ToolListProcesses:
                        return await HandleListProcessesAsync(context.CancellationToken);
                    case ToolAttach:
                        return await HandleAttachAsync(request.ArgsJson, context.CancellationToken);
                    case ToolListModules:
                        return await HandleListModulesAsync(request.ArgsJson, context.CancellationToken);
                    case ToolListExports:
                        return await HandleListExportsAsync(request.ArgsJson, context.CancellationToken);
                    case ToolReadMemory:
                        return await HandleReadMemoryAsync(request.ArgsJson, context.CancellationToken);
                    case ToolReadString:
                        return await HandleReadStringAsync(request.ArgsJson, context.CancellationToken);
                    case ToolScanMemory:
                        return await HandleScanMemoryAsync(request.ArgsJson, context.CancellationToken);
                    case ToolWriteMemory:
                        return await HandleWriteMemoryAsync(request.ArgsJson, context.CancellationToken);
                    case ToolCallFunction:
                        return await HandleCallFunctionAsync(request.ArgsJson, context.CancellationToken);
                    case ToolSpawn:
                        return await HandleSpawnAsync(request.ArgsJson, context.CancellationToken);
                    case ToolResume:
                        return await HandleResumeAsync(request.ArgsJson, context.CancellationToken);
                    case ToolKill:
                        return await HandleKillAsync(request.ArgsJson, context.CancellationToken);
                    case ToolHookStart:
                        return await HandleHookStartAsync(request.ArgsJson, false, context.CancellationToken);
                    case ToolHookPoll:
                        return await HandleHookPollAsync(request.ArgsJson);
                    case ToolHookStop:
                        return await HandleHookStopAsync(request.ArgsJson);
                    case ToolSetBreakpoint:
                        return await HandleHookStartAsync(request.ArgsJson, true, context.CancellationToken);
                    case ToolScriptLoad:
                        return await HandleScriptLoadAsync(request.ArgsJson, context.CancellationToken);
                    case ToolScriptUnload:
                        return await HandleScriptUnloadAsync(request.ArgsJson);
                    case ToolScriptMessagePoll:
                        return await HandleScriptMessagePollAsync(request.ArgsJson);
                    case ToolRpcCall:
                        return await HandleRpcCallAsync(request.ArgsJson, context.CancellationToken);
                    case ToolScriptPost:
                        return await HandleScriptPostAsync(request.ArgsJson);
                    case ToolTestStrings:
                        return await HandleTestStringsAsync(request.ArgsJson, context.CancellationToken);
                    default:
                        return new InvokeToolReply { Error = $"Unknown tool: {request.Name}" };
                }
            }
            catch (Exception ex)
            {
                return new InvokeToolReply { Error = ex.Message };
            }
        }

        private async Task<InvokeToolReply> HandleListProcessesAsync(CancellationToken cancellationToken)
        {
            var processes = await _cli.ListProcessesAsync(cancellationToken);
            var payload = JsonSerializer.Serialize(processes);
            return new InvokeToolReply { ResultJson = BuildTextContent(payload) };
        }

        private async Task<InvokeToolReply> HandleAttachAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetInt(args, "pid", out var pid))
                return new InvokeToolReply { Error = "pid gerekli" };

            var sessionId = _sessions.CreateSession(pid);
            var attachResult = await _cli.AttachAsync(pid, cancellationToken);
            var envelope = JsonSerializer.Serialize(new { sessionId, pid, attach = attachResult });
            return new InvokeToolReply { ResultJson = BuildTextContent(envelope) };
        }

        private async Task<InvokeToolReply> HandleListModulesAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            var data = await _cli.ListModulesAsync(pid, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleListExportsAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "module", out var moduleName))
                return new InvokeToolReply { Error = "module gerekli" };

            var data = await _cli.ListExportsAsync(pid, moduleName, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private Task<InvokeToolReply> HandleReadMemoryAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return Task.FromResult(new InvokeToolReply { Error = "address gecersiz" });

            if (!TryGetInt(args, "size", out var size) || size <= 0)
                return Task.FromResult(new InvokeToolReply { Error = "size gecersiz" });

            if (!TryResolvePid(args, out var pid, out error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            return HandleReadMemoryAsync(pid, addressText, size, cancellationToken);
        }

        private static string BuildTextContent(string text)
        {
            var content = new[] { new ContentItem("text", text) };
            return JsonSerializer.Serialize(content);
        }

        private static bool TryParseArgs(string argsJson, out JsonElement args, out string? error)
        {
            error = null;
            args = default;

            if (string.IsNullOrWhiteSpace(argsJson))
            {
                error = "argsJson bos";
                return false;
            }

            try
            {
                using (var doc = JsonDocument.Parse(argsJson))
                {
                    if (doc.RootElement.ValueKind != JsonValueKind.Object)
                    {
                        error = "argsJson object olmali";
                        return false;
                    }

                    args = doc.RootElement.Clone();
                    return true;
                }
            }
            catch (JsonException ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static bool TryGetInt(JsonElement args, string name, out int value)
        {
            value = 0;
            if (!args.TryGetProperty(name, out var element))
                return false;

            return element.TryGetInt32(out value);
        }

        private static bool TryGetString(JsonElement args, string name, out string value)
        {
            value = string.Empty;
            if (!args.TryGetProperty(name, out var element))
                return false;

            if (element.ValueKind != JsonValueKind.String)
                return false;

            value = element.GetString() ?? string.Empty;
            return value.Length > 0;
        }

        private static bool TryGetBool(JsonElement args, string name, out bool value)
        {
            value = false;
            if (!args.TryGetProperty(name, out var element))
                return false;

            if (element.ValueKind == JsonValueKind.True)
            {
                value = true;
                return true;
            }

            if (element.ValueKind == JsonValueKind.False)
            {
                value = false;
                return true;
            }

            return false;
        }

        private static bool TryGetArray(JsonElement args, string name, out JsonElement value)
        {
            value = default;
            if (!args.TryGetProperty(name, out var element))
                return false;

            if (element.ValueKind != JsonValueKind.Array)
                return false;

            value = element;
            return true;
        }

        private static bool TryParseAddress(string text, out ulong address)
        {
            address = 0;
            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                return ulong.TryParse(text.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out address);

            return ulong.TryParse(text, out address);
        }

        private bool TryResolvePid(JsonElement args, out int pid, out string error)
        {
            error = string.Empty;
            pid = 0;

            if (TryGetInt(args, "pid", out pid))
                return true;

            if (TryGetString(args, "sessionId", out var sessionId) && _sessions.TryGetPid(sessionId, out pid))
                return true;

            error = "pid veya sessionId gerekli";
            return false;
        }

        private async Task<InvokeToolReply> HandleReadMemoryAsync(int pid, string address, int size, CancellationToken cancellationToken)
        {
            var data = await _cli.ReadMemoryAsync(pid, address, size, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleReadStringAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return new InvokeToolReply { Error = "address gecersiz" };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            var maxLength = 256;
            if (TryGetInt(args, "maxLength", out var maxValue) && maxValue > 0)
                maxLength = maxValue;

            var encoding = "utf8";
            if (TryGetString(args, "encoding", out var encValue))
                encoding = encValue;

            try
            {
                var data = await _cli.ReadStringAsync(pid, addressText, maxLength, encoding, cancellationToken);
                return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "read_string fallback: pid={Pid} addr={Address} enc={Encoding}", pid, addressText, encoding);
                return await HandleReadStringFallbackAsync(pid, addressText, maxLength, encoding, cancellationToken, ex.Message);
            }
        }

        private async Task<InvokeToolReply> HandleScanMemoryAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return new InvokeToolReply { Error = "address gecersiz" };

            if (!TryGetInt(args, "size", out var size) || size <= 0)
                return new InvokeToolReply { Error = "size gecersiz" };

            if (!TryGetString(args, "pattern", out var pattern))
                return new InvokeToolReply { Error = "pattern gerekli" };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            var data = await _cli.ScanMemoryAsync(pid, addressText, size, pattern, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleWriteMemoryAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return new InvokeToolReply { Error = "address gecersiz" };

            if (!TryGetString(args, "dataHex", out var dataHex) && !TryGetString(args, "data", out dataHex))
                return new InvokeToolReply { Error = "dataHex gerekli" };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            var data = await _cli.WriteMemoryAsync(pid, addressText, dataHex, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleCallFunctionAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return new InvokeToolReply { Error = "address gecersiz" };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            if (!TryGetArray(args, "argTypes", out var argTypesElement))
                return new InvokeToolReply { Error = "argTypes gerekli" };

            if (!TryGetArray(args, "argValues", out var argValuesElement))
                return new InvokeToolReply { Error = "argValues gerekli" };

            if (argTypesElement.GetArrayLength() != argValuesElement.GetArrayLength())
                return new InvokeToolReply { Error = "argTypes/argValues sayisi uyusmuyor" };

            var returnType = "pointer";
            if (TryGetString(args, "returnType", out var returnTypeValue))
                returnType = returnTypeValue;

            var data = await _cli.CallFunctionAsync(
                pid,
                addressText,
                returnType,
                argTypesElement.GetRawText(),
                argValuesElement.GetRawText(),
                cancellationToken);

            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleSpawnAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "program", out var program) && !TryGetString(args, "path", out program))
                return new InvokeToolReply { Error = "program gerekli" };

            var argList = Array.Empty<string>();
            if (TryGetArray(args, "args", out var argsElement))
            {
                var list = new List<string>();
                foreach (var item in argsElement.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        var value = item.GetString();
                        if (!string.IsNullOrWhiteSpace(value))
                            list.Add(value);
                    }
                    else if (item.ValueKind != JsonValueKind.Null && item.ValueKind != JsonValueKind.Undefined)
                    {
                        var value = item.ToString();
                        if (!string.IsNullOrWhiteSpace(value))
                            list.Add(value);
                    }
                }

                argList = list.ToArray();
            }

            var argsPayload = JsonSerializer.Serialize(argList);
            var data = await _cli.SpawnAsync(program, argsPayload, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleResumeAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetInt(args, "pid", out var pid))
                return new InvokeToolReply { Error = "pid gerekli" };

            var data = await _cli.ResumeAsync(pid, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private async Task<InvokeToolReply> HandleKillAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetInt(args, "pid", out var pid))
                return new InvokeToolReply { Error = "pid gerekli" };

            var data = await _cli.KillAsync(pid, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
        }

        private Task<InvokeToolReply> HandleHookStartAsync(string argsJson, bool breakpointMode, CancellationToken cancellationToken)
        {
            _ = cancellationToken;
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryResolvePid(args, out var pid, out error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryBuildHookTarget(args, out var targetExpr, out var targetLabel, out error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            var includeArgs = true;
            var includeRetval = false;
            var includeBacktrace = false;
            if (TryGetBool(args, "includeArgs", out var includeArgsValue))
                includeArgs = includeArgsValue;
            if (TryGetBool(args, "includeRetval", out var includeRetvalValue))
                includeRetval = includeRetvalValue;
            if (TryGetBool(args, "includeBacktrace", out var includeBacktraceValue))
                includeBacktrace = includeBacktraceValue;

            var maxArgs = 6;
            if (TryGetInt(args, "maxArgs", out var maxArgsValue) && maxArgsValue >= 0)
                maxArgs = Math.Min(16, maxArgsValue);

            var autoStop = breakpointMode;
            if (TryGetBool(args, "autoStop", out var autoStopValue))
                autoStop = autoStopValue;

            var once = breakpointMode;
            var hasOnce = TryGetBool(args, "once", out var onceValue);
            if (hasOnce)
                once = onceValue;
            if (autoStop && !hasOnce)
                once = true;

            var scriptSource = BuildHookScript(targetExpr, targetLabel, includeArgs, includeRetval, includeBacktrace, maxArgs, once);
            var hookId = _hookManager.StartHook(pid, scriptSource, autoStop);

            var payload = JsonSerializer.Serialize(new { hookId, pid, target = targetLabel, autoStop });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private Task<InvokeToolReply> HandleHookPollAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "hookId", out var hookId))
                return Task.FromResult(new InvokeToolReply { Error = "hookId gerekli" });

            var maxEvents = 25;
            if (TryGetInt(args, "maxEvents", out var maxEventsValue) && maxEventsValue > 0)
                maxEvents = Math.Min(200, maxEventsValue);

            var events = _hookManager.PollEvents(hookId, maxEvents);
            var parsedEvents = ParseHookEvents(events);
            var payload = JsonSerializer.Serialize(new { hookId, events = parsedEvents });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private Task<InvokeToolReply> HandleHookStopAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "hookId", out var hookId))
                return Task.FromResult(new InvokeToolReply { Error = "hookId gerekli" });

            var stopped = _hookManager.StopHook(hookId);
            var payload = JsonSerializer.Serialize(new { hookId, stopped });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private Task<InvokeToolReply> HandleScriptLoadAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryResolvePid(args, out var pid, out error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "source", out var source) || string.IsNullOrWhiteSpace(source))
                return Task.FromResult(new InvokeToolReply { Error = "source gerekli" });

            _ = cancellationToken;
            var scriptId = _scriptManager.StartScript(pid, source);
            var payload = JsonSerializer.Serialize(new { scriptId, pid });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private Task<InvokeToolReply> HandleScriptUnloadAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "scriptId", out var scriptId))
                return Task.FromResult(new InvokeToolReply { Error = "scriptId gerekli" });

            var stopped = _scriptManager.StopScript(scriptId);
            var payload = JsonSerializer.Serialize(new { scriptId, stopped });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private Task<InvokeToolReply> HandleScriptMessagePollAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "scriptId", out var scriptId))
                return Task.FromResult(new InvokeToolReply { Error = "scriptId gerekli" });

            var maxEvents = 25;
            if (TryGetInt(args, "maxEvents", out var maxEventsValue) && maxEventsValue > 0)
                maxEvents = Math.Min(200, maxEventsValue);

            var events = _scriptManager.PollMessages(scriptId, maxEvents);
            var parsedEvents = ParseHookEvents(events);
            var payload = JsonSerializer.Serialize(new { scriptId, events = parsedEvents });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private async Task<InvokeToolReply> HandleRpcCallAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryGetString(args, "scriptId", out var scriptId))
                return new InvokeToolReply { Error = "scriptId gerekli" };

            if (!TryGetString(args, "method", out var method))
                return new InvokeToolReply { Error = "method gerekli" };

            var timeoutMs = _options.TimeoutMs;
            if (TryGetInt(args, "timeoutMs", out var timeoutValue) && timeoutValue > 0)
                timeoutMs = timeoutValue;

            var argsPayload = "[]";
            if (args.TryGetProperty("args", out var argsElement) && argsElement.ValueKind != JsonValueKind.Undefined)
                argsPayload = argsElement.GetRawText();

            try
            {
                var result = await _scriptManager.RpcCallAsync(scriptId, method, argsPayload, timeoutMs, cancellationToken);
                var payload = JsonSerializer.Serialize(new { result });
                return new InvokeToolReply { ResultJson = BuildTextContent(payload) };
            }
            catch (Exception ex)
            {
                return new InvokeToolReply { Error = ex.Message };
            }
        }

        private Task<InvokeToolReply> HandleScriptPostAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(new InvokeToolReply { Error = error });

            if (!TryGetString(args, "scriptId", out var scriptId))
                return Task.FromResult(new InvokeToolReply { Error = "scriptId gerekli" });

            if (!args.TryGetProperty("payload", out var payloadElement))
                return Task.FromResult(new InvokeToolReply { Error = "payload gerekli" });

            var payloadJson = payloadElement.GetRawText();
            var ok = _scriptManager.PostMessage(scriptId, payloadJson);
            var payload = JsonSerializer.Serialize(new { scriptId, ok });
            return Task.FromResult(new InvokeToolReply { ResultJson = BuildTextContent(payload) });
        }

        private async Task<InvokeToolReply> HandleTestStringsAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return new InvokeToolReply { Error = error };

            if (!TryResolvePid(args, out var pid, out error))
                return new InvokeToolReply { Error = error };

            var asciiText = "FRIDA_ASCII_TEST: CreateFileA VirtualAlloc ExitProcess";
            if (TryGetString(args, "asciiText", out var asciiValue))
                asciiText = asciiValue;

            var utf16Text = "FRIDA_UTF16_TEST: CreateProcessW VirtualProtectW";
            if (TryGetString(args, "utf16Text", out var utf16Value))
                utf16Text = utf16Value;

            var timeoutMs = _options.TimeoutMs;
            if (TryGetInt(args, "timeoutMs", out var timeoutValue) && timeoutValue > 0)
                timeoutMs = timeoutValue;

            var scriptSource = BuildTestStringScript(asciiText, utf16Text);
            var scriptId = _scriptManager.StartScript(pid, scriptSource);

            var info = await WaitForTestStringInfoAsync(scriptId, timeoutMs, cancellationToken);
            if (info != null)
            {
                var payload = JsonSerializer.Serialize(new
                {
                    scriptId,
                    asciiText,
                    utf16Text,
                    asciiPtr = info.AsciiPtr,
                    utf16Ptr = info.Utf16Ptr
                });
                return new InvokeToolReply { ResultJson = BuildTextContent(payload) };
            }

            var fallbackPayload = JsonSerializer.Serialize(new
            {
                scriptId,
                asciiText,
                utf16Text,
                pending = true
            });
            return new InvokeToolReply { ResultJson = BuildTextContent(fallbackPayload) };
        }

        private static bool TryBuildHookTarget(JsonElement args, out string targetExpr, out string targetLabel, out string error)
        {
            targetExpr = string.Empty;
            targetLabel = string.Empty;
            error = string.Empty;

            if (TryGetString(args, "address", out var addressText))
            {
                if (!TryParseAddress(addressText, out _))
                {
                    error = "address gecersiz";
                    return false;
                }

                targetExpr = $"ptr({JsonSerializer.Serialize(addressText)})";
                targetLabel = addressText;
                return true;
            }

            if (TryGetString(args, "export", out var exportName) || TryGetString(args, "exportName", out exportName))
            {
                var moduleExpr = "null";
                var moduleLabel = string.Empty;
                if (TryGetString(args, "module", out var moduleName))
                {
                    moduleExpr = JsonSerializer.Serialize(moduleName);
                    moduleLabel = moduleName;
                }

                targetExpr = $"resolveExport({moduleExpr}, {JsonSerializer.Serialize(exportName)})";
                targetLabel = string.IsNullOrWhiteSpace(moduleLabel) ? exportName : $"{moduleLabel}!{exportName}";
                return true;
            }

            error = "address veya module+export gerekli";
            return false;
        }

        private static string BuildHookScript(
            string targetExpr,
            string targetLabel,
            bool includeArgs,
            bool includeRetval,
            bool includeBacktrace,
            int maxArgs,
            bool once)
        {
            var labelJson = JsonSerializer.Serialize(targetLabel);
            var builder = new StringBuilder();
            builder.AppendLine("'use strict';");
            builder.AppendLine("setImmediate(function(){");
            builder.AppendLine("  try {");
            builder.AppendLine($"    var target = {targetExpr};");
            builder.AppendLine("    if (!target) { send({ event: 'error', message: 'target null' }); return; }");
            builder.AppendLine($"    var label = {labelJson};");
            builder.AppendLine($"    var includeArgs = {(includeArgs ? "true" : "false")};");
            builder.AppendLine($"    var includeRetval = {(includeRetval ? "true" : "false")};");
            builder.AppendLine($"    var includeBacktrace = {(includeBacktrace ? "true" : "false")};");
            builder.AppendLine($"    var maxArgs = {maxArgs};");
            builder.AppendLine($"    var once = {(once ? "true" : "false")};");
            builder.AppendLine("    function resolveExport(moduleName, exportName){");
            builder.AppendLine("      try {");
            builder.AppendLine("        if (typeof Module !== 'undefined') {");
            builder.AppendLine("          if (typeof Module.getExportByName === 'function') return Module.getExportByName(moduleName, exportName);");
            builder.AppendLine("          if (typeof Module.findExportByName === 'function') return Module.findExportByName(moduleName, exportName);");
            builder.AppendLine("        }");
            builder.AppendLine("        if (moduleName && typeof Process !== 'undefined' && typeof Process.getModuleByName === 'function') {");
            builder.AppendLine("          var mod = Process.getModuleByName(moduleName);");
            builder.AppendLine("          if (mod && typeof mod.getExportByName === 'function') return mod.getExportByName(exportName);");
            builder.AppendLine("        }");
            builder.AppendLine("        if (!moduleName && typeof Process !== 'undefined' && typeof Process.enumerateModulesSync === 'function') {");
            builder.AppendLine("          var mods = Process.enumerateModulesSync();");
            builder.AppendLine("          for (var i = 0; i < mods.length; i++) {");
            builder.AppendLine("            try { return mods[i].getExportByName(exportName); } catch (e) { }");
            builder.AppendLine("          }");
            builder.AppendLine("        }");
            builder.AppendLine("      } catch (e) { }");
            builder.AppendLine("      return null;");
            builder.AppendLine("    }");
            builder.AppendLine("    function safeToString(value){ try { return value.toString(); } catch (e) { return '<err>'; } }");
            builder.AppendLine("    function buildArgs(args){");
            builder.AppendLine("      if (!includeArgs || maxArgs <= 0) return [];");
            builder.AppendLine("      var list = [];");
            builder.AppendLine("      for (var i = 0; i < maxArgs; i++) {");
            builder.AppendLine("        try {");
            builder.AppendLine("          var value = args[i];");
            builder.AppendLine("          if (value === undefined) break;");
            builder.AppendLine("          list.push(value.toString());");
            builder.AppendLine("        } catch (e) {");
            builder.AppendLine("          break;");
            builder.AppendLine("        }");
            builder.AppendLine("      }");
            builder.AppendLine("      return list;");
            builder.AppendLine("    }");
            builder.AppendLine("    function buildBacktrace(ctx){");
            builder.AppendLine("      if (!includeBacktrace) return [];");
            builder.AppendLine("      var frames = Thread.backtrace(ctx, Backtracer.ACCURATE);");
            builder.AppendLine("      return frames.map(function(addr){ return DebugSymbol.fromAddress(addr).toString(); });");
            builder.AppendLine("    }");
            builder.AppendLine("    Interceptor.attach(target, {");
            builder.AppendLine("      onEnter: function(args){");
            builder.AppendLine("        var payload = { event: 'enter', label: label, address: target.toString() };");
            builder.AppendLine("        if (includeArgs) payload.args = buildArgs(args);");
            builder.AppendLine("        if (includeBacktrace) payload.backtrace = buildBacktrace(this.context);");
            builder.AppendLine("        send(payload);");
            builder.AppendLine("        if (once) {");
            builder.AppendLine("          Interceptor.detachAll();");
            builder.AppendLine("          send({ event: 'detached', label: label, address: target.toString() });");
            builder.AppendLine("        }");
            builder.AppendLine("      },");
            builder.AppendLine("      onLeave: function(retval){");
            builder.AppendLine("        if (!includeRetval) return;");
            builder.AppendLine("        var payload = { event: 'leave', label: label, address: target.toString(), retval: safeToString(retval) };");
            builder.AppendLine("        send(payload);");
            builder.AppendLine("      }");
            builder.AppendLine("    });");
            builder.AppendLine("    send({ event: 'ready', label: label, address: target.toString() });");
            builder.AppendLine("  } catch (e) {");
            builder.AppendLine("    send({ event: 'error', message: e.message || e.toString() });");
            builder.AppendLine("  }");
            builder.AppendLine("});");
            return builder.ToString();
        }

        private static string BuildTestStringScript(string asciiText, string utf16Text)
        {
            var asciiJson = JsonSerializer.Serialize(asciiText);
            var utf16Json = JsonSerializer.Serialize(utf16Text);
            var builder = new StringBuilder();
            builder.AppendLine("'use strict';");
            builder.AppendLine("setImmediate(function(){");
            builder.AppendLine("  try {");
            builder.AppendLine($"    var ascii = {asciiJson};");
            builder.AppendLine($"    var utf16 = {utf16Json};");
            builder.AppendLine("    var asciiPtr = Memory.allocUtf8String(ascii);");
            builder.AppendLine("    var utf16Ptr = Memory.allocUtf16String(utf16);");
            builder.AppendLine("    send({ type: 'test_strings', ascii: ascii, utf16: utf16, asciiPtr: asciiPtr.toString(), utf16Ptr: utf16Ptr.toString() });");
            builder.AppendLine("    rpc.exports = {");
            builder.AppendLine("      getaddrs: function(){ return { asciiPtr: asciiPtr.toString(), utf16Ptr: utf16Ptr.toString() }; }");
            builder.AppendLine("    };");
            builder.AppendLine("  } catch (e) {");
            builder.AppendLine("    send({ type: 'test_strings_error', error: e.message || e.toString() });");
            builder.AppendLine("  }");
            builder.AppendLine("});");
            return builder.ToString();
        }

        private async Task<TestStringInfo?> WaitForTestStringInfoAsync(string scriptId, int timeoutMs, CancellationToken cancellationToken)
        {
            var stopwatch = Stopwatch.StartNew();
            while (stopwatch.ElapsedMilliseconds < timeoutMs)
            {
                var events = _scriptManager.PollMessages(scriptId, 10);
                foreach (var raw in events)
                {
                    if (TryParseTestStringInfo(raw, out var info))
                        return info;
                }

                try
                {
                    await Task.Delay(50, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    return null;
                }
            }

            return null;
        }

        private static bool TryParseTestStringInfo(string raw, out TestStringInfo? info)
        {
            info = null;
            if (string.IsNullOrWhiteSpace(raw))
                return false;

            try
            {
                using var doc = JsonDocument.Parse(raw);
                var root = doc.RootElement;
                if (!root.TryGetProperty("type", out var typeElement) || typeElement.ValueKind != JsonValueKind.String)
                    return false;

                if (!string.Equals(typeElement.GetString(), "send", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!root.TryGetProperty("payload", out var payloadElement) || payloadElement.ValueKind != JsonValueKind.Object)
                    return false;

                if (!payloadElement.TryGetProperty("type", out var payloadType) || payloadType.ValueKind != JsonValueKind.String)
                    return false;

                if (!string.Equals(payloadType.GetString(), "test_strings", StringComparison.OrdinalIgnoreCase))
                    return false;

                if (!payloadElement.TryGetProperty("asciiPtr", out var asciiElement) || asciiElement.ValueKind != JsonValueKind.String)
                    return false;

                if (!payloadElement.TryGetProperty("utf16Ptr", out var utf16Element) || utf16Element.ValueKind != JsonValueKind.String)
                    return false;

                info = new TestStringInfo(asciiElement.GetString() ?? string.Empty, utf16Element.GetString() ?? string.Empty);
                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        private static List<JsonElement> ParseHookEvents(IReadOnlyList<string> events)
        {
            var parsed = new List<JsonElement>(events.Count);
            foreach (var raw in events)
            {
                if (string.IsNullOrWhiteSpace(raw))
                    continue;

                if (TryParseJsonElement(raw, out var element))
                {
                    parsed.Add(element);
                    continue;
                }

                parsed.Add(BuildRawEvent(raw));
            }

            return parsed;
        }

        private static bool TryParseJsonElement(string text, out JsonElement element)
        {
            element = default;
            try
            {
                using var doc = JsonDocument.Parse(text);
                element = doc.RootElement.Clone();
                return true;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        private static JsonElement BuildRawEvent(string text)
        {
            using var doc = JsonDocument.Parse(JsonSerializer.Serialize(new { type = "raw", payload = text }));
            return doc.RootElement.Clone();
        }

        private async Task<InvokeToolReply> HandleReadStringFallbackAsync(
            int pid,
            string addressText,
            int maxLength,
            string encoding,
            CancellationToken cancellationToken,
            string error)
        {
            var bytesToRead = GetReadStringFallbackSize(maxLength, encoding);
            try
            {
                var mem = await _cli.ReadMemoryAsync(pid, addressText, bytesToRead, cancellationToken);
                var decoded = DecodeStringFromMemory(mem, encoding, maxLength);
                var payload = JsonSerializer.Serialize(new
                {
                    data = decoded,
                    fallback = true,
                    encoding,
                    bytesRead = bytesToRead,
                    error
                });
                return new InvokeToolReply { ResultJson = BuildTextContent(payload) };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "read_string fallback failed: pid={Pid} addr={Address}", pid, addressText);
                return new InvokeToolReply { Error = $"{error}; fallback failed: {ex.Message}" };
            }
        }

        private static int GetReadStringFallbackSize(int maxLength, string encoding)
        {
            if (IsUtf16(encoding))
                return Math.Max(2, maxLength * 2);

            return Math.Max(1, maxLength);
        }

        private static string DecodeStringFromMemory(JsonElement mem, string encoding, int maxLength)
        {
            if (!mem.TryGetProperty("data", out var dataElement) || dataElement.ValueKind != JsonValueKind.String)
                return string.Empty;

            var hex = dataElement.GetString() ?? string.Empty;
            if (hex.Length == 0)
                return string.Empty;

            var bytes = HexToBytes(hex);
            if (bytes.Length == 0)
                return string.Empty;

            var trimmed = TrimAtNull(bytes, IsUtf16(encoding));
            var enc = ResolveEncoding(encoding);
            var text = enc.GetString(trimmed);
            return text.Length > maxLength ? text.Substring(0, maxLength) : text;
        }

        private static byte[] HexToBytes(string hex)
        {
            var clean = hex.Trim();
            if (clean.Length % 2 != 0)
                clean = "0" + clean;

            var bytes = new byte[clean.Length / 2];
            for (var i = 0; i < bytes.Length; i++)
            {
                var span = clean.AsSpan(i * 2, 2);
                if (!byte.TryParse(span, System.Globalization.NumberStyles.HexNumber, null, out var value))
                    return Array.Empty<byte>();
                bytes[i] = value;
            }

            return bytes;
        }

        private static byte[] TrimAtNull(byte[] bytes, bool utf16)
        {
            if (utf16)
            {
                for (var i = 0; i + 1 < bytes.Length; i += 2)
                {
                    if (bytes[i] == 0 && bytes[i + 1] == 0)
                        return bytes[..i];
                }

                return bytes;
            }

            for (var i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == 0)
                    return bytes[..i];
            }

            return bytes;
        }

        private static Encoding ResolveEncoding(string encoding)
        {
            var enc = encoding.Trim().ToLowerInvariant();
            return enc switch
            {
                "ascii" => Encoding.ASCII,
                "latin1" => Encoding.Latin1,
                "iso-8859-1" => Encoding.Latin1,
                "utf16" => Encoding.Unicode,
                "utf-16" => Encoding.Unicode,
                _ => Encoding.UTF8
            };
        }

        private static bool IsUtf16(string encoding)
        {
            var enc = encoding.Trim().ToLowerInvariant();
            return enc == "utf16" || enc == "utf-16";
        }

        private static string BuildPayload(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Undefined)
                return "{}";

            return element.GetRawText();
        }

        private sealed record TestStringInfo(string AsciiPtr, string Utf16Ptr);

        private sealed record ContentItem(string type, string text);
    }
}
