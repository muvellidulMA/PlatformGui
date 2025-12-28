using Grpc.Core;
using Mcp.Worker.Frida.App.Options;
using Mcp.Workers.Protocol;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
namespace Mcp.Worker.Frida.App.Services
{
    public sealed class FridaWorkerService : global::Mcp.Workers.Protocol.Worker.WorkerBase
    {
        private const string ToolListProcesses = "list_processes";
        private const string ToolAttach = "attach";
        private const string ToolDetach = "detach";
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
        private const string ToolSelfTest = "self_test";

        private const string ErrorInvalidArgs = "INVALID_ARGS";
        private const string ErrorPolicyBlock = "POLICY_BLOCK";
        private const string ErrorRuntime = "RUNTIME";
        private const string ErrorTimeout = "TIMEOUT";
        private const string ErrorNotFound = "NOT_FOUND";

        private readonly FridaCli _cli;
        private readonly FridaSessionStore _sessions;
        private readonly FridaSessionManager _sessionManager;
        private readonly FridaOptions _options;
        private readonly FridaHookManager _hookManager;
        private readonly FridaScriptManager _scriptManager;
        private readonly FridaToolPolicy _policy;
        private readonly ILogger<FridaWorkerService> _logger;

        public FridaWorkerService(
            FridaCli cli,
            FridaSessionStore sessions,
            FridaSessionManager sessionManager,
            FridaOptions options,
            FridaHookManager hookManager,
            FridaScriptManager scriptManager,
            FridaToolPolicy policy,
            ILogger<FridaWorkerService> logger)
        {
            _cli = cli;
            _sessions = sessions;
            _sessionManager = sessionManager;
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
                        Description = "Proses listesi. Gerekli: yok. Cikti: {ok:true,data:[{pid,name}]}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": {}, ""additionalProperties"": false }"
                    },
                    new ToolInfo
                    {
                        Name = ToolAttach,
                        Description = "Proses attach. Gerekli: pid. Cikti: {ok:true,data:{sessionId,pid,attach}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolDetach,
                        Description = "Session kapatir. Gerekli: sessionId. Cikti: {ok:true,data:{sessionId,removed,stopped}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""sessionId"": { ""type"": ""string"" } }, ""required"": [""sessionId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolListModules,
                        Description = "Modul listesi. Gerekli: pid veya sessionId. Cikti: {ok:true,data:{data:[{name,base,size,path}]}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolListExports,
                        Description = "Modul export listesi. Gerekli: pid veya sessionId, module. Cikti: {ok:true,data:{data:[{name,address,type}]}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" } }, ""required"": [""module""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolReadMemory,
                        Description = "Bellekten hex okur. Gerekli: pid veya sessionId, address, size. Cikti: {ok:true,data:{data,size}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""size"": { ""type"": ""integer"" } }, ""required"": [""address"", ""size""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolReadString,
                        Description = "Bellekten string okur. Gerekli: pid veya sessionId, address. Opsiyonel: maxChars, maxBytes, maxLength, encoding. Cikti: {ok:true,data:{data,encoding,bytesRead,terminated,fallback,maxChars,maxBytes}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""maxChars"": { ""type"": ""integer"" }, ""maxBytes"": { ""type"": ""integer"" }, ""maxLength"": { ""type"": ""integer"" }, ""encoding"": { ""type"": ""string"" } }, ""required"": [""address""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScanMemory,
                        Description = "Bellek tarama. Gerekli: pid veya sessionId, address, size, pattern. Cikti: {ok:true,data:{data:[address...]}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""size"": { ""type"": ""integer"" }, ""pattern"": { ""type"": ""string"" } }, ""required"": [""address"", ""size"", ""pattern""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolWriteMemory,
                        Description = "Bellege hex yazar. Gerekli: pid veya sessionId, address, dataHex. Cikti: {ok:true,data:{data:{written}}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""dataHex"": { ""type"": ""string"" } }, ""required"": [""address"", ""dataHex""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolCallFunction,
                        Description = "Adresteki fonksiyonu cagirir. Gerekli: pid veya sessionId, address, argTypes, argValues. Opsiyonel: returnType. Cikti: {ok:true,data:{data:{result}}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""returnType"": { ""type"": ""string"" }, ""argTypes"": { ""type"": ""array"", ""items"": { ""type"": ""string"" } }, ""argValues"": { ""type"": ""array"", ""items"": {} } }, ""required"": [""address"", ""argTypes"", ""argValues""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolSpawn,
                        Description = "Proses spawn (suspended). Gerekli: program (veya path). Opsiyonel: args. Cikti: {ok:true,data:{pid,argv}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""program"": { ""type"": ""string"" }, ""path"": { ""type"": ""string"" }, ""args"": { ""type"": ""array"", ""items"": { ""type"": ""string"" } } }, ""required"": [""program""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolResume,
                        Description = "Spawn edilen prosesi devam ettirir. Gerekli: pid. Cikti: {ok:true,data:{pid,resumed}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolKill,
                        Description = "Proses sonlandirir. Gerekli: pid. Cikti: {ok:true,data:{pid,killed}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookStart,
                        Description = "Hook baslatir. Gerekli: pid veya sessionId, address veya module+export. Opsiyonel: includeArgs, includeRetval, includeBacktrace, maxArgs, once, autoStop, stream, pollIntervalMs, maxEvents. Cikti: {ok:true,data:{hookId,pid,target,autoStop}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" }, ""export"": { ""type"": ""string"" }, ""maxArgs"": { ""type"": ""integer"" }, ""includeArgs"": { ""type"": ""boolean"" }, ""includeBacktrace"": { ""type"": ""boolean"" }, ""includeRetval"": { ""type"": ""boolean"" }, ""once"": { ""type"": ""boolean"" }, ""autoStop"": { ""type"": ""boolean"" }, ""stream"": { ""type"": ""boolean"" }, ""pollIntervalMs"": { ""type"": ""integer"" }, ""maxEvents"": { ""type"": ""integer"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookPoll,
                        Description = "Hook event okur. Gerekli: hookId. Opsiyonel: maxEvents. Cikti: {ok:true,data:{hookId,events:[...]}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""hookId"": { ""type"": ""string"" }, ""maxEvents"": { ""type"": ""integer"" } }, ""required"": [""hookId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookStop,
                        Description = "Hook durdurur. Gerekli: hookId. Cikti: {ok:true,data:{hookId,stopped}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""hookId"": { ""type"": ""string"" } }, ""required"": [""hookId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolSetBreakpoint,
                        Description = "Breakpoint (hook tabanli). Gerekli: pid veya sessionId, address veya module+export. Opsiyonel: includeArgs, includeRetval, includeBacktrace, maxArgs, once, autoStop, stream, pollIntervalMs, maxEvents. Cikti: {ok:true,data:{hookId,pid,target,autoStop}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" }, ""export"": { ""type"": ""string"" }, ""maxArgs"": { ""type"": ""integer"" }, ""includeArgs"": { ""type"": ""boolean"" }, ""includeBacktrace"": { ""type"": ""boolean"" }, ""once"": { ""type"": ""boolean"" }, ""stream"": { ""type"": ""boolean"" }, ""pollIntervalMs"": { ""type"": ""integer"" }, ""maxEvents"": { ""type"": ""integer"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptLoad,
                        Description = "Script inject eder. Gerekli: pid veya sessionId, source. Cikti: {ok:true,data:{scriptId,pid}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""source"": { ""type"": ""string"" } }, ""required"": [""source""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptUnload,
                        Description = "Script kaldirir. Gerekli: scriptId. Cikti: {ok:true,data:{scriptId,stopped}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" } }, ""required"": [""scriptId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptMessagePoll,
                        Description = "Script mesajlarini okur. Gerekli: scriptId. Opsiyonel: maxEvents. Cikti: {ok:true,data:{scriptId,events:[...]}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" }, ""maxEvents"": { ""type"": ""integer"" } }, ""required"": [""scriptId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolRpcCall,
                        Description = "rpc.exports method cagirir. Gerekli: scriptId, method. Opsiyonel: args, timeoutMs. Cikti: {ok:true,data:{result}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" }, ""method"": { ""type"": ""string"" }, ""args"": { ""type"": ""array"", ""items"": {} }, ""timeoutMs"": { ""type"": ""integer"" } }, ""required"": [""scriptId"", ""method""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScriptPost,
                        Description = "Script recv icin payload gonderir. Gerekli: scriptId, payload. Cikti: {ok:true,data:{scriptId,ok}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""scriptId"": { ""type"": ""string"" }, ""payload"": { ""type"": [""object"", ""array"", ""string"", ""number"", ""boolean""] } }, ""required"": [""scriptId"", ""payload""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolTestStrings,
                        Description = "Test string allocate eder. Gerekli: pid veya sessionId. Opsiyonel: asciiText, utf16Text, timeoutMs. Cikti: {ok:true,data:{scriptId,asciiPtr,utf16Ptr}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""asciiText"": { ""type"": ""string"" }, ""utf16Text"": { ""type"": ""string"" }, ""timeoutMs"": { ""type"": ""integer"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolSelfTest,
                        Description = "Kendi kendine test harness. Gerekli: yok. Opsiyonel: pid, module, timeoutMs. Cikti: {ok:true,data:{summary,capabilities,logPath,logs}}. Hata: {ok:false,error:{kind,detail}}.",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""module"": { ""type"": ""string"" }, ""timeoutMs"": { ""type"": ""integer"" } }, ""additionalProperties"": false }"
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
                    return BuildErrorReply(ErrorPolicyBlock, string.IsNullOrWhiteSpace(decision.Detail) ? "blocked" : decision.Detail);

                switch (request.Name)
                {
                    case ToolListProcesses:
                        return await HandleListProcessesAsync(context.CancellationToken);
                    case ToolAttach:
                        return await HandleAttachAsync(request.ArgsJson, context.CancellationToken);
                    case ToolDetach:
                        return await HandleDetachAsync(request.ArgsJson, context.CancellationToken);
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
                    case ToolSelfTest:
                        return await HandleSelfTestAsync(request.ArgsJson, context.CancellationToken);
                    default:
                        return BuildErrorReply(ErrorNotFound, $"Unknown tool: {request.Name}");
                }
            }
            catch (OperationCanceledException ex)
            {
                return BuildErrorReply(ErrorTimeout, ex.Message);
            }
            catch (TimeoutException ex)
            {
                return BuildErrorReply(ErrorTimeout, ex.Message);
            }
            catch (Exception ex)
            {
                var kind = GetErrorKind(ex);
                return BuildErrorReply(kind, ex.Message);
            }
        }

        private async Task<InvokeToolReply> HandleListProcessesAsync(CancellationToken cancellationToken)
        {
            var processes = await _cli.ListProcessesAsync(cancellationToken);
            var data = processes.Select(p => new { pid = p.Pid, name = p.Name }).ToArray();
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleAttachAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error ?? "argsJson gecersiz");

            if (!TryGetInt(args, "pid", out var pid))
                return BuildErrorReply(ErrorInvalidArgs, "pid gerekli");

            var attachResult = await _cli.AttachAsync(pid, cancellationToken);
            var sessionId = _sessions.CreateSession(pid);
            _sessionManager.StartSession(sessionId, pid);
            return BuildOkReply(new { sessionId, pid, attach = attachResult });
        }

        private Task<InvokeToolReply> HandleDetachAsync(string argsJson, CancellationToken cancellationToken)
        {
            _ = cancellationToken;
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "sessionId", out var sessionId))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "sessionId gerekli"));

            var removed = _sessions.RemoveSession(sessionId);
            var stopped = _sessionManager.StopSession(sessionId);
            return Task.FromResult(BuildOkReply(new { sessionId, removed, stopped }));
        }

        private async Task<InvokeToolReply> HandleListModulesAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return BuildErrorReply(ErrorNotFound, error);

                var payload = JsonSerializer.SerializeToElement(new { });
                var sessionData = await _sessionManager.CallAsync(sessionId, "list_modules", payload, _options.TimeoutMs, cancellationToken);
                return BuildOkReply(sessionData);
            }

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            var data = await _cli.ListModulesAsync(pid, cancellationToken);
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleListExportsAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "module", out var moduleName))
                return BuildErrorReply(ErrorInvalidArgs, "module gerekli");

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return BuildErrorReply(ErrorNotFound, error);

                var payload = JsonSerializer.SerializeToElement(new { module = moduleName });
                var sessionData = await _sessionManager.CallAsync(sessionId, "list_exports", payload, _options.TimeoutMs, cancellationToken);
                return BuildOkReply(sessionData);
            }

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            var data = await _cli.ListExportsAsync(pid, moduleName, cancellationToken);
            return BuildOkReply(data);
        }

        private Task<InvokeToolReply> HandleReadMemoryAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "address gecersiz"));

            if (!TryGetInt(args, "size", out var size) || size <= 0)
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "size gecersiz"));

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return Task.FromResult(BuildErrorReply(ErrorNotFound, error));

                var payload = JsonSerializer.SerializeToElement(new { address = addressText, size });
                return HandleSessionCallAsync(sessionId, "read_memory", payload, cancellationToken);
            }

            if (!TryResolvePid(args, out var pid, out error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

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
                args = JsonDocument.Parse("{}").RootElement.Clone();
                return true;
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

        private static bool TryGetSessionId(JsonElement args, out string sessionId)
            => TryGetString(args, "sessionId", out sessionId);

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

        private bool TryEnsureSession(string sessionId, out string error)
        {
            error = string.Empty;
            if (_sessionManager.HasSession(sessionId))
                return true;

            if (_sessions.TryGetPid(sessionId, out var pid))
            {
                _sessionManager.StartSession(sessionId, pid);
                return true;
            }

            error = "sessionId bulunamadi";
            return false;
        }

        private async Task<InvokeToolReply> HandleReadMemoryAsync(int pid, string address, int size, CancellationToken cancellationToken)
        {
            var data = await _cli.ReadMemoryAsync(pid, address, size, cancellationToken);
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleSessionCallAsync(string sessionId, string op, JsonElement payload, CancellationToken cancellationToken)
        {
            var data = await _sessionManager.CallAsync(sessionId, op, payload, _options.TimeoutMs, cancellationToken);
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleReadStringAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return BuildErrorReply(ErrorInvalidArgs, "address gecersiz");

            var encoding = "utf8";
            if (TryGetString(args, "encoding", out var encValue))
                encoding = encValue;

            ResolveReadStringLimits(args, encoding, out var maxChars, out var maxBytes);

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return BuildErrorReply(ErrorNotFound, error);

                var payload = JsonSerializer.SerializeToElement(new { address = addressText, maxLength = maxChars, encoding });
                var data = await _sessionManager.CallAsync(sessionId, "read_string", payload, _options.TimeoutMs, cancellationToken);
                var result = BuildReadStringResult(data, encoding, maxChars, maxBytes, fallback: false, fallbackError: null);
                return BuildOkReply(result);
            }

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            try
            {
                var data = await _cli.ReadStringAsync(pid, addressText, maxChars, encoding, cancellationToken);
                var result = BuildReadStringResult(data, encoding, maxChars, maxBytes, fallback: false, fallbackError: null);
                return BuildOkReply(result);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "read_string fallback: pid={Pid} addr={Address} enc={Encoding}", pid, addressText, encoding);
                return await HandleReadStringFallbackAsync(pid, addressText, maxChars, maxBytes, encoding, cancellationToken, ex.Message);
            }
        }

        private async Task<InvokeToolReply> HandleScanMemoryAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return BuildErrorReply(ErrorInvalidArgs, "address gecersiz");

            if (!TryGetInt(args, "size", out var size) || size <= 0)
                return BuildErrorReply(ErrorInvalidArgs, "size gecersiz");

            if (!TryGetString(args, "pattern", out var pattern))
                return BuildErrorReply(ErrorInvalidArgs, "pattern gerekli");

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return BuildErrorReply(ErrorNotFound, error);

                var payload = JsonSerializer.SerializeToElement(new { address = addressText, size, pattern });
                var sessionData = await _sessionManager.CallAsync(sessionId, "scan_memory", payload, _options.TimeoutMs, cancellationToken);
                return BuildOkReply(sessionData);
            }

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            var data = await _cli.ScanMemoryAsync(pid, addressText, size, pattern, cancellationToken);
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleWriteMemoryAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return BuildErrorReply(ErrorInvalidArgs, "address gecersiz");

            if (!TryGetString(args, "dataHex", out var dataHex) && !TryGetString(args, "data", out dataHex))
                return BuildErrorReply(ErrorInvalidArgs, "dataHex gerekli");

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return BuildErrorReply(ErrorNotFound, error);

                var payload = JsonSerializer.SerializeToElement(new { address = addressText, dataHex });
                var sessionData = await _sessionManager.CallAsync(sessionId, "write_memory", payload, _options.TimeoutMs, cancellationToken);
                return BuildOkReply(sessionData);
            }

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            var data = await _cli.WriteMemoryAsync(pid, addressText, dataHex, cancellationToken);
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleCallFunctionAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "address", out var addressText) || !TryParseAddress(addressText, out _))
                return BuildErrorReply(ErrorInvalidArgs, "address gecersiz");

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetArray(args, "argTypes", out var argTypesElement))
                return BuildErrorReply(ErrorInvalidArgs, "argTypes gerekli");

            if (!TryGetArray(args, "argValues", out var argValuesElement))
                return BuildErrorReply(ErrorInvalidArgs, "argValues gerekli");

            if (argTypesElement.GetArrayLength() != argValuesElement.GetArrayLength())
                return BuildErrorReply(ErrorInvalidArgs, "argTypes/argValues sayisi uyusmuyor");

            var returnType = "pointer";
            if (TryGetString(args, "returnType", out var returnTypeValue))
                returnType = returnTypeValue;

            if (TryGetSessionId(args, out var sessionId))
            {
                if (!TryEnsureSession(sessionId, out error))
                    return BuildErrorReply(ErrorNotFound, error);

                var payload = JsonSerializer.SerializeToElement(new
                {
                    address = addressText,
                    returnType,
                    argTypes = JsonSerializer.Deserialize<string[]>(argTypesElement.GetRawText()) ?? Array.Empty<string>(),
                    argValues = JsonSerializer.Deserialize<object[]>(argValuesElement.GetRawText()) ?? Array.Empty<object>()
                });
                var sessionData = await _sessionManager.CallAsync(sessionId, "call_function", payload, _options.TimeoutMs, cancellationToken);
                return BuildOkReply(sessionData);
            }

            var data = await _cli.CallFunctionAsync(
                pid,
                addressText,
                returnType,
                argTypesElement.GetRawText(),
                argValuesElement.GetRawText(),
                cancellationToken);

            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleSpawnAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "program", out var program) && !TryGetString(args, "path", out program))
                return BuildErrorReply(ErrorInvalidArgs, "program gerekli");

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
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleResumeAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetInt(args, "pid", out var pid))
                return BuildErrorReply(ErrorInvalidArgs, "pid gerekli");

            var data = await _cli.ResumeAsync(pid, cancellationToken);
            return BuildOkReply(data);
        }

        private async Task<InvokeToolReply> HandleKillAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetInt(args, "pid", out var pid))
                return BuildErrorReply(ErrorInvalidArgs, "pid gerekli");

            var data = await _cli.KillAsync(pid, cancellationToken);
            return BuildOkReply(data);
        }

        private Task<InvokeToolReply> HandleHookStartAsync(string argsJson, bool breakpointMode, CancellationToken cancellationToken)
        {
            _ = cancellationToken;
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryResolvePid(args, out var pid, out error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryBuildHookTarget(args, out var targetExpr, out var targetLabel, out error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

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

            return Task.FromResult(BuildOkReply(new { hookId, pid, target = targetLabel, autoStop }));
        }

        private Task<InvokeToolReply> HandleHookPollAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "hookId", out var hookId))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "hookId gerekli"));

            var maxEvents = 25;
            if (TryGetInt(args, "maxEvents", out var maxEventsValue) && maxEventsValue > 0)
                maxEvents = Math.Min(200, maxEventsValue);

            var events = _hookManager.PollEvents(hookId, maxEvents);
            var parsedEvents = ParseHookEvents(events);
            return Task.FromResult(BuildOkReply(new { hookId, events = parsedEvents }));
        }

        private Task<InvokeToolReply> HandleHookStopAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "hookId", out var hookId))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "hookId gerekli"));

            var stopped = _hookManager.StopHook(hookId);
            return Task.FromResult(BuildOkReply(new { hookId, stopped }));
        }

        private Task<InvokeToolReply> HandleScriptLoadAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryResolvePid(args, out var pid, out error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "source", out var source) || string.IsNullOrWhiteSpace(source))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "source gerekli"));

            _ = cancellationToken;
            var scriptId = _scriptManager.StartScript(pid, source);
            return Task.FromResult(BuildOkReply(new { scriptId, pid }));
        }

        private Task<InvokeToolReply> HandleScriptUnloadAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "scriptId", out var scriptId))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "scriptId gerekli"));

            var stopped = _scriptManager.StopScript(scriptId);
            return Task.FromResult(BuildOkReply(new { scriptId, stopped }));
        }

        private Task<InvokeToolReply> HandleScriptMessagePollAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "scriptId", out var scriptId))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "scriptId gerekli"));

            var maxEvents = 25;
            if (TryGetInt(args, "maxEvents", out var maxEventsValue) && maxEventsValue > 0)
                maxEvents = Math.Min(200, maxEventsValue);

            var events = _scriptManager.PollMessages(scriptId, maxEvents);
            var parsedEvents = ParseHookEvents(events);
            return Task.FromResult(BuildOkReply(new { scriptId, events = parsedEvents }));
        }

        private async Task<InvokeToolReply> HandleRpcCallAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryGetString(args, "scriptId", out var scriptId))
                return BuildErrorReply(ErrorInvalidArgs, "scriptId gerekli");

            if (!TryGetString(args, "method", out var method))
                return BuildErrorReply(ErrorInvalidArgs, "method gerekli");

            var timeoutMs = _options.TimeoutMs;
            if (TryGetInt(args, "timeoutMs", out var timeoutValue) && timeoutValue > 0)
                timeoutMs = timeoutValue;

            var argsPayload = "[]";
            if (args.TryGetProperty("args", out var argsElement) && argsElement.ValueKind != JsonValueKind.Undefined)
                argsPayload = argsElement.GetRawText();

            var result = await _scriptManager.RpcCallAsync(scriptId, method, argsPayload, timeoutMs, cancellationToken);
            return BuildOkReply(new { result });
        }

        private Task<InvokeToolReply> HandleScriptPostAsync(string argsJson)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, error));

            if (!TryGetString(args, "scriptId", out var scriptId))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "scriptId gerekli"));

            if (!args.TryGetProperty("payload", out var payloadElement))
                return Task.FromResult(BuildErrorReply(ErrorInvalidArgs, "payload gerekli"));

            var payloadJson = payloadElement.GetRawText();
            var ok = _scriptManager.PostMessage(scriptId, payloadJson);
            return Task.FromResult(BuildOkReply(new { scriptId, ok }));
        }

        private async Task<InvokeToolReply> HandleTestStringsAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            if (!TryResolvePid(args, out var pid, out error))
                return BuildErrorReply(ErrorInvalidArgs, error);

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
                var payload = new
                {
                    scriptId,
                    asciiText,
                    utf16Text,
                    asciiPtr = info.AsciiPtr,
                    utf16Ptr = info.Utf16Ptr
                };
                return BuildOkReply(payload);
            }

            var fallbackPayload = new
            {
                scriptId,
                asciiText,
                utf16Text,
                pending = true
            };
            return BuildOkReply(fallbackPayload);
        }

        private async Task<InvokeToolReply> HandleSelfTestAsync(string argsJson, CancellationToken cancellationToken)
        {
            if (!TryParseArgs(argsJson, out var args, out var error))
                return BuildErrorReply(ErrorInvalidArgs, error);

            int? pid = null;
            if (TryGetInt(args, "pid", out var pidValue) && pidValue > 0)
                pid = pidValue;

            string? moduleHint = null;
            if (TryGetString(args, "module", out var moduleValue))
                moduleHint = moduleValue;

            var timeoutMs = _options.TimeoutMs;
            if (TryGetInt(args, "timeoutMs", out var timeoutValue) && timeoutValue > 0)
                timeoutMs = timeoutValue;

            var logPath = Path.Combine(Path.GetTempPath(), $"frida_self_test_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}.jsonl");
            using var writer = new StreamWriter(logPath, false, new UTF8Encoding(false));
            var logs = new List<string>();
            var capabilities = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            void WriteLog(string step, string status, object? data = null, string? detail = null)
            {
                var entry = new
                {
                    ts = DateTime.UtcNow.ToString("O"),
                    step,
                    status,
                    detail,
                    data
                };
                var line = JsonSerializer.Serialize(entry);
                writer.WriteLine(line);
                writer.Flush();
                logs.Add(line);
                capabilities[step] = status;
            }

            try
            {
                var list = await _cli.ListProcessesAsync(cancellationToken);
                WriteLog("list_processes", "pass", new { count = list.Count });
            }
            catch (Exception ex)
            {
                WriteLog("list_processes", "fail", null, ex.Message);
            }

            if (pid == null)
            {
                WriteLog("attach", "skip", null, "pid verilmedi");
                WriteLog("list_modules", "skip", null, "pid verilmedi");
                WriteLog("list_exports", "skip", null, "pid verilmedi");
                WriteLog("read_memory", "skip", null, "pid verilmedi");
                WriteLog("read_string", "skip", null, "pid verilmedi");
                WriteLog("scan_memory", "skip", null, "pid verilmedi");
                WriteLog("write_memory", "skip", null, "pid verilmedi");
                WriteLog("call_function", "skip", null, "pid verilmedi");
                WriteLog("hook_start", "skip", null, "pid verilmedi");
                WriteLog("hook_poll", "skip", null, "pid verilmedi");
                WriteLog("hook_stop", "skip", null, "pid verilmedi");
                WriteLog("script_load", "skip", null, "pid verilmedi");
                WriteLog("script_message_poll", "skip", null, "pid verilmedi");
                WriteLog("rpc_call", "skip", null, "pid verilmedi");
                WriteLog("script_post", "skip", null, "pid verilmedi");
                WriteLog("script_unload", "skip", null, "pid verilmedi");
                WriteLog("test_strings", "skip", null, "pid verilmedi");
                WriteLog("spawn", "skip", null, "program gerekli");
                WriteLog("resume", "skip", null, "pid gerekli");
                WriteLog("kill", "skip", null, "pid gerekli");

                return BuildOkReply(new
                {
                    summary = BuildSummary(capabilities),
                    capabilities,
                    logPath,
                    logs = logs.TakeLast(200).ToArray()
                });
            }

            var sessionId = _sessions.CreateSession(pid.Value);
            _sessionManager.StartSession(sessionId, pid.Value);

            try
            {
                try
                {
                    var attachInfo = await _cli.AttachAsync(pid.Value, cancellationToken);
                    WriteLog("attach", "pass", attachInfo);
                }
                catch (Exception ex)
                {
                    WriteLog("attach", "fail", null, ex.Message);
                }

                JsonElement modulePayload = default;
                string? moduleName = moduleHint;
                string? moduleBase = null;
                try
                {
                    modulePayload = await _sessionManager.CallAsync(sessionId, "list_modules", JsonSerializer.SerializeToElement(new { }), timeoutMs, cancellationToken);
                    if (TryGetDataArray(modulePayload, out var modules))
                    {
                        foreach (var item in modules.EnumerateArray())
                        {
                            if (moduleName == null && item.TryGetProperty("name", out var nameElement) && nameElement.ValueKind == JsonValueKind.String)
                                moduleName = nameElement.GetString();
                            if (moduleBase == null && item.TryGetProperty("base", out var baseElement) && baseElement.ValueKind == JsonValueKind.String)
                                moduleBase = baseElement.GetString();
                            if (moduleName != null && moduleBase != null)
                                break;
                        }
                    }
                    WriteLog("list_modules", "pass", new { moduleName, moduleBase });
                }
                catch (Exception ex)
                {
                    WriteLog("list_modules", "fail", null, ex.Message);
                }

                string? exportName = null;
                string? exportAddress = null;
                if (!string.IsNullOrWhiteSpace(moduleName))
                {
                    try
                    {
                        var exportsPayload = await _sessionManager.CallAsync(sessionId, "list_exports", JsonSerializer.SerializeToElement(new { module = moduleName }), timeoutMs, cancellationToken);
                        if (TryGetDataArray(exportsPayload, out var exports))
                        {
                            var candidates = new[] { "GetTickCount", "GetCurrentProcessId", "GetCurrentThreadId" };
                            foreach (var item in exports.EnumerateArray())
                            {
                                if (!item.TryGetProperty("name", out var nameElement) || nameElement.ValueKind != JsonValueKind.String)
                                    continue;
                                var name = nameElement.GetString() ?? string.Empty;
                                if (!candidates.Any(c => string.Equals(c, name, StringComparison.OrdinalIgnoreCase)))
                                    continue;
                                exportName = name;
                                if (item.TryGetProperty("address", out var addrElement) && addrElement.ValueKind == JsonValueKind.String)
                                    exportAddress = addrElement.GetString();
                                break;
                            }
                        }
                        WriteLog("list_exports", "pass", new { moduleName, exportName, exportAddress });
                    }
                    catch (Exception ex)
                    {
                        WriteLog("list_exports", "fail", null, ex.Message);
                    }
                }
                else
                {
                    WriteLog("list_exports", "skip", null, "module bulunamadi");
                }

                if (!string.IsNullOrWhiteSpace(moduleBase))
                {
                    try
                    {
                        var memPayload = await _sessionManager.CallAsync(sessionId, "read_memory", JsonSerializer.SerializeToElement(new { address = moduleBase, size = 32 }), timeoutMs, cancellationToken);
                        WriteLog("read_memory", "pass", memPayload);
                    }
                    catch (Exception ex)
                    {
                        WriteLog("read_memory", "fail", null, ex.Message);
                    }
                }
                else
                {
                    WriteLog("read_memory", "skip", null, "module base bulunamadi");
                }

                string? asciiPtr = null;
                string asciiText = "FRIDA_ASCII_TEST: CreateFileA VirtualAlloc ExitProcess";
                try
                {
                    var testScriptId = _scriptManager.StartScript(pid.Value, BuildTestStringScript(asciiText, "FRIDA_UTF16_TEST: CreateProcessW VirtualProtectW"));
                    var info = await WaitForTestStringInfoAsync(testScriptId, timeoutMs, cancellationToken);
                    if (info != null)
                    {
                        asciiPtr = info.AsciiPtr;
                        WriteLog("test_strings", "pass", new { scriptId = testScriptId, asciiPtr = info.AsciiPtr, utf16Ptr = info.Utf16Ptr });
                    }
                    else
                    {
                        WriteLog("test_strings", "fail", null, "test_strings timeout");
                    }
                    _scriptManager.StopScript(testScriptId);
                }
                catch (Exception ex)
                {
                    WriteLog("test_strings", "fail", null, ex.Message);
                }

                if (!string.IsNullOrWhiteSpace(asciiPtr))
                {
                    try
                    {
                        var readPayload = await _sessionManager.CallAsync(sessionId, "read_string", JsonSerializer.SerializeToElement(new { address = asciiPtr, maxLength = 128, encoding = "ascii" }), timeoutMs, cancellationToken);
                        var readResult = BuildReadStringResult(readPayload, "ascii", 128, 128, fallback: false, fallbackError: null);
                        WriteLog("read_string", "pass", readResult);
                    }
                    catch (Exception ex)
                    {
                        WriteLog("read_string", "fail", null, ex.Message);
                    }

                    try
                    {
                        var pattern = BuildHexPattern(asciiText);
                        var scanPayload = await _sessionManager.CallAsync(sessionId, "scan_memory", JsonSerializer.SerializeToElement(new { address = asciiPtr, size = asciiText.Length + 32, pattern }), timeoutMs, cancellationToken);
                        WriteLog("scan_memory", "pass", scanPayload);
                    }
                    catch (Exception ex)
                    {
                        WriteLog("scan_memory", "fail", null, ex.Message);
                    }

                    try
                    {
                        var writeText = "MCP_SELF_TEST";
                        var writeHex = BuildHexPattern(writeText);
                        var writePayload = await _sessionManager.CallAsync(sessionId, "write_memory", JsonSerializer.SerializeToElement(new { address = asciiPtr, dataHex = writeHex }), timeoutMs, cancellationToken);
                        WriteLog("write_memory", "pass", writePayload);
                    }
                    catch (Exception ex)
                    {
                        WriteLog("write_memory", "fail", null, ex.Message);
                    }
                }
                else
                {
                    WriteLog("read_string", "skip", null, "asciiPtr yok");
                    WriteLog("scan_memory", "skip", null, "asciiPtr yok");
                    WriteLog("write_memory", "skip", null, "asciiPtr yok");
                }

                if (!string.IsNullOrWhiteSpace(exportAddress))
                {
                    try
                    {
                        var callPayload = await _sessionManager.CallAsync(sessionId, "call_function", JsonSerializer.SerializeToElement(new
                        {
                            address = exportAddress,
                            returnType = "uint32",
                            argTypes = Array.Empty<string>(),
                            argValues = Array.Empty<object>()
                        }), timeoutMs, cancellationToken);
                        WriteLog("call_function", "pass", callPayload);
                    }
                    catch (Exception ex)
                    {
                        WriteLog("call_function", "fail", null, ex.Message);
                    }

                    string? hookId = null;
                    try
                    {
                        var targetExpr = $"ptr({JsonSerializer.Serialize(exportAddress)})";
                        var scriptSource = BuildHookScript(targetExpr, exportName ?? exportAddress, includeArgs: true, includeRetval: false, includeBacktrace: false, maxArgs: 4, once: true);
                        hookId = _hookManager.StartHook(pid.Value, scriptSource, autoStopOnFirstEvent: true);
                        WriteLog("hook_start", "pass", new { hookId });

                        await _sessionManager.CallAsync(sessionId, "call_function", JsonSerializer.SerializeToElement(new
                        {
                            address = exportAddress,
                            returnType = "uint32",
                            argTypes = Array.Empty<string>(),
                            argValues = Array.Empty<object>()
                        }), timeoutMs, cancellationToken);

                        var events = _hookManager.PollEvents(hookId, 10);
                        var parsedEvents = ParseHookEvents(events);
                        WriteLog("hook_poll", parsedEvents.Count > 0 ? "pass" : "fail", new { hookId, events = parsedEvents });

                        var stopped = _hookManager.StopHook(hookId);
                        WriteLog("hook_stop", stopped ? "pass" : "fail", new { hookId, stopped });
                    }
                    catch (Exception ex)
                    {
                        WriteLog("hook_start", "fail", null, ex.Message);
                        if (!string.IsNullOrWhiteSpace(hookId))
                            _hookManager.StopHook(hookId);
                    }
                }
                else
                {
                    WriteLog("call_function", "skip", null, "export bulunamadi");
                    WriteLog("hook_start", "skip", null, "export bulunamadi");
                    WriteLog("hook_poll", "skip", null, "export bulunamadi");
                    WriteLog("hook_stop", "skip", null, "export bulunamadi");
                }

                string? scriptId = null;
                try
                {
                    var scriptSource = BuildSelfTestScript();
                    scriptId = _scriptManager.StartScript(pid.Value, scriptSource);
                    WriteLog("script_load", "pass", new { scriptId });

                    var events = _scriptManager.PollMessages(scriptId, 10);
                    WriteLog("script_message_poll", events.Count > 0 ? "pass" : "fail", new { scriptId, events = ParseHookEvents(events) });

                    var rpcResult = await _scriptManager.RpcCallAsync(scriptId, "ping", JsonSerializer.Serialize(new[] { "hi" }), timeoutMs, cancellationToken);
                    WriteLog("rpc_call", "pass", new { scriptId, result = rpcResult });

                    var postOk = _scriptManager.PostMessage(scriptId, JsonSerializer.Serialize(new { hello = "world" }));
                    WriteLog("script_post", postOk ? "pass" : "fail", new { scriptId, ok = postOk });

                    var postEvents = _scriptManager.PollMessages(scriptId, 10);
                    WriteLog("script_message_poll", postEvents.Count > 0 ? "pass" : "fail", new { scriptId, events = ParseHookEvents(postEvents) });

                    var unload = _scriptManager.StopScript(scriptId);
                    WriteLog("script_unload", unload ? "pass" : "fail", new { scriptId, stopped = unload });
                }
                catch (Exception ex)
                {
                    WriteLog("script_load", "fail", null, ex.Message);
                    if (!string.IsNullOrWhiteSpace(scriptId))
                        _scriptManager.StopScript(scriptId);
                }

                WriteLog("spawn", "skip", null, "program gerekli");
                WriteLog("resume", "skip", null, "pid gerekli");
                WriteLog("kill", "skip", null, "pid gerekli");
            }
            finally
            {
                var sessionStopped = _sessionManager.StopSession(sessionId);
                var sessionRemoved = _sessions.RemoveSession(sessionId);
                WriteLog("detach", sessionStopped || sessionRemoved ? "pass" : "fail", new { sessionId, stopped = sessionStopped, removed = sessionRemoved });
            }

            return BuildOkReply(new
            {
                summary = BuildSummary(capabilities),
                capabilities,
                logPath,
                logs = logs.TakeLast(200).ToArray()
            });
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
            int maxChars,
            int maxBytes,
            string encoding,
            CancellationToken cancellationToken,
            string error)
        {
            var bytesToRead = maxBytes > 0 ? maxBytes : GetReadStringFallbackSize(maxChars, encoding);
            try
            {
                var mem = await _cli.ReadMemoryAsync(pid, addressText, bytesToRead, cancellationToken);
                var decoded = DecodeStringFromMemory(mem, encoding, maxChars);
                var bytesRead = GetBytesRead(mem, bytesToRead);
                var payload = new
                {
                    data = decoded.Text,
                    encoding = decoded.Encoding,
                    bytesRead,
                    terminated = decoded.Terminated,
                    fallback = true,
                    fallbackError = error,
                    maxChars,
                    maxBytes = bytesToRead
                };
                return BuildOkReply(payload);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "read_string fallback failed: pid={Pid} addr={Address}", pid, addressText);
                return BuildErrorReply(ErrorRuntime, $"{error}; fallback failed: {ex.Message}");
            }
        }

        private static int GetReadStringFallbackSize(int maxChars, string encoding)
        {
            if (IsUtf16(encoding))
                return Math.Max(2, maxChars * 2);

            return Math.Max(1, maxChars);
        }

        private static DecodedString DecodeStringFromMemory(JsonElement mem, string encoding, int maxChars)
        {
            if (!mem.TryGetProperty("data", out var dataElement) || dataElement.ValueKind != JsonValueKind.String)
                return new DecodedString(string.Empty, ResolveEncodingName(encoding), false);

            var hex = dataElement.GetString() ?? string.Empty;
            if (hex.Length == 0)
                return new DecodedString(string.Empty, ResolveEncodingName(encoding), false);

            var bytes = HexToBytes(hex);
            if (bytes.Length == 0)
                return new DecodedString(string.Empty, ResolveEncodingName(encoding), false);

            var trimResult = TrimAtNull(bytes, IsUtf16(encoding));
            var enc = ResolveEncoding(encoding);
            var text = enc.GetString(trimResult.Bytes);
            if (text.Length > maxChars)
                text = text.Substring(0, maxChars);

            return new DecodedString(text, ResolveEncodingName(encoding), trimResult.Terminated);
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

        private static TrimResult TrimAtNull(byte[] bytes, bool utf16)
        {
            if (utf16)
            {
                for (var i = 0; i + 1 < bytes.Length; i += 2)
                {
                    if (bytes[i] == 0 && bytes[i + 1] == 0)
                        return new TrimResult(bytes[..i], true);
                }

                return new TrimResult(bytes, false);
            }

            for (var i = 0; i < bytes.Length; i++)
            {
                if (bytes[i] == 0)
                    return new TrimResult(bytes[..i], true);
            }

            return new TrimResult(bytes, false);
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

        private static string ResolveEncodingName(string encoding)
        {
            var enc = encoding.Trim().ToLowerInvariant();
            return enc switch
            {
                "ascii" => "ascii",
                "latin1" => "latin1",
                "iso-8859-1" => "latin1",
                "utf16" => "utf16",
                "utf-16" => "utf16",
                _ => "utf8"
            };
        }

        private static bool IsUtf16(string encoding)
        {
            var enc = encoding.Trim().ToLowerInvariant();
            return enc == "utf16" || enc == "utf-16";
        }

        private static void ResolveReadStringLimits(JsonElement args, string encoding, out int maxChars, out int maxBytes)
        {
            maxChars = 256;
            maxBytes = 0;

            if (TryGetInt(args, "maxChars", out var maxCharsValue) && maxCharsValue > 0)
                maxChars = maxCharsValue;
            else if (TryGetInt(args, "maxLength", out var maxLengthValue) && maxLengthValue > 0)
                maxChars = maxLengthValue;

            if (TryGetInt(args, "maxBytes", out var maxBytesValue) && maxBytesValue > 0)
                maxBytes = maxBytesValue;

            if (maxBytes > 0)
            {
                maxChars = IsUtf16(encoding) ? Math.Max(1, maxBytes / 2) : maxBytes;
            }
            else
            {
                maxBytes = GetReadStringFallbackSize(maxChars, encoding);
            }
        }

        private static object BuildReadStringResult(JsonElement payload, string encoding, int maxChars, int maxBytes, bool fallback, string? fallbackError)
        {
            var text = string.Empty;
            var resolvedEncoding = ResolveEncodingName(encoding);
            var bytesRead = 0;
            var terminated = false;

            if (payload.ValueKind == JsonValueKind.Object)
            {
                if (payload.TryGetProperty("data", out var dataElement) && dataElement.ValueKind == JsonValueKind.String)
                    text = dataElement.GetString() ?? string.Empty;

                if (payload.TryGetProperty("encoding", out var encElement) && encElement.ValueKind == JsonValueKind.String)
                    resolvedEncoding = ResolveEncodingName(encElement.GetString() ?? resolvedEncoding);

                if (payload.TryGetProperty("bytesRead", out var bytesElement) && bytesElement.TryGetInt32(out var bytesValue))
                    bytesRead = bytesValue;

                if (payload.TryGetProperty("terminated", out var termElement))
                {
                    if (termElement.ValueKind == JsonValueKind.True)
                        terminated = true;
                    else if (termElement.ValueKind == JsonValueKind.False)
                        terminated = false;
                }
            }
            else if (payload.ValueKind == JsonValueKind.String)
            {
                text = payload.GetString() ?? string.Empty;
            }

            if (bytesRead == 0)
                bytesRead = maxBytes;

            return new
            {
                data = text,
                encoding = resolvedEncoding,
                bytesRead,
                terminated,
                fallback,
                fallbackError,
                maxChars,
                maxBytes
            };
        }

        private static int GetBytesRead(JsonElement mem, int fallback)
        {
            if (mem.ValueKind == JsonValueKind.Object &&
                mem.TryGetProperty("size", out var sizeElement) &&
                sizeElement.TryGetInt32(out var sizeValue))
                return sizeValue;

            return fallback;
        }

        private static object BuildSummary(Dictionary<string, string> capabilities)
        {
            var pass = capabilities.Count(pair => string.Equals(pair.Value, "pass", StringComparison.OrdinalIgnoreCase));
            var fail = capabilities.Count(pair => string.Equals(pair.Value, "fail", StringComparison.OrdinalIgnoreCase));
            var skip = capabilities.Count(pair => string.Equals(pair.Value, "skip", StringComparison.OrdinalIgnoreCase));
            return new { pass, fail, skip, total = capabilities.Count };
        }

        private static bool TryGetDataArray(JsonElement payload, out JsonElement array)
        {
            array = default;
            if (payload.ValueKind == JsonValueKind.Object &&
                payload.TryGetProperty("data", out var dataElement) &&
                dataElement.ValueKind == JsonValueKind.Array)
            {
                array = dataElement;
                return true;
            }

            if (payload.ValueKind == JsonValueKind.Array)
            {
                array = payload;
                return true;
            }

            return false;
        }

        private static string BuildHexPattern(string text)
        {
            var bytes = Encoding.ASCII.GetBytes(text);
            var builder = new StringBuilder(bytes.Length * 3);
            for (var i = 0; i < bytes.Length; i++)
            {
                if (i > 0)
                    builder.Append(' ');
                builder.Append(bytes[i].ToString("X2"));
            }
            return builder.ToString();
        }

        private static string BuildSelfTestScript()
        {
            var builder = new StringBuilder();
            builder.AppendLine("'use strict';");
            builder.AppendLine("rpc.exports = {");
            builder.AppendLine("  ping: function(msg){ return 'pong:' + msg; }");
            builder.AppendLine("};");
            builder.AppendLine("recv(function(message){");
            builder.AppendLine("  send({ type: 'recv_echo', payload: message });");
            builder.AppendLine("  recv(arguments.callee);");
            builder.AppendLine("});");
            builder.AppendLine("send({ type: 'ready' });");
            return builder.ToString();
        }

        private static string BuildOkPayload(JsonElement element)
        {
            object? data = element.ValueKind == JsonValueKind.Undefined ? null : element;
            return JsonSerializer.Serialize(new { ok = true, data });
        }

        private static string BuildOkPayload(object? data)
        {
            return JsonSerializer.Serialize(new { ok = true, data });
        }

        private static string BuildErrorPayload(string kind, string? detail)
        {
            return JsonSerializer.Serialize(new { ok = false, error = new { kind, detail = detail ?? "bilinmeyen hata" } });
        }

        private static InvokeToolReply BuildOkReply(object? data)
            => new InvokeToolReply { ResultJson = BuildTextContent(BuildOkPayload(data)) };

        private static InvokeToolReply BuildOkReply(JsonElement data)
            => new InvokeToolReply { ResultJson = BuildTextContent(BuildOkPayload(data)) };

        private static InvokeToolReply BuildErrorReply(string kind, string? detail)
            => new InvokeToolReply { Error = BuildErrorPayload(kind, detail) };

        private static string GetErrorKind(Exception ex)
        {
            if (ex is OperationCanceledException || ex is TimeoutException)
                return ErrorTimeout;

            var message = ex.Message ?? string.Empty;
            if (message.Contains("timeout", StringComparison.OrdinalIgnoreCase))
                return ErrorTimeout;

            return ErrorRuntime;
        }

        private sealed record TestStringInfo(string AsciiPtr, string Utf16Ptr);

        private sealed record TrimResult(byte[] Bytes, bool Terminated);

        private sealed record DecodedString(string Text, string Encoding, bool Terminated);

        private sealed record ContentItem(string type, string text);
    }
}
