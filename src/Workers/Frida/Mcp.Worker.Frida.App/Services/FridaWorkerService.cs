using Grpc.Core;
using Mcp.Worker.Frida.App.Options;
using Mcp.Workers.Protocol;
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
        private const string ToolHookStart = "hook_start";
        private const string ToolHookPoll = "hook_poll";
        private const string ToolHookStop = "hook_stop";
        private const string ToolSetBreakpoint = "set_breakpoint";

        private readonly FridaCli _cli;
        private readonly FridaSessionStore _sessions;
        private readonly FridaOptions _options;
        private readonly FridaHookManager _hookManager;

        public FridaWorkerService(FridaCli cli, FridaSessionStore sessions, FridaOptions options, FridaHookManager hookManager)
        {
            _cli = cli;
            _sessions = sessions;
            _options = options;
            _hookManager = hookManager;
        }

        public override Task<ListToolsReply> ListTools(ListToolsRequest request, ServerCallContext context)
            => Task.FromResult(new ListToolsReply
            {
                Tools =
                {
                    new ToolInfo
                    {
                        Name = ToolListProcesses,
                        Description = "Frida process listesi",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": {}, ""additionalProperties"": false }"
                    },
                    new ToolInfo
                    {
                        Name = ToolAttach,
                        Description = "Frida attach (session id dondurur)",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" } }, ""required"": [""pid""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolListModules,
                        Description = "Frida list_modules",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolListExports,
                        Description = "Frida list_exports",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" } }, ""required"": [""module""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolReadMemory,
                        Description = "Frida read_memory (hex dondurur)",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""size"": { ""type"": ""integer"" } }, ""required"": [""address"", ""size""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolReadString,
                        Description = "Frida read_string",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""maxLength"": { ""type"": ""integer"" }, ""encoding"": { ""type"": ""string"" } }, ""required"": [""address""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolScanMemory,
                        Description = "Frida scan_memory",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""size"": { ""type"": ""integer"" }, ""pattern"": { ""type"": ""string"" } }, ""required"": [""address"", ""size"", ""pattern""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolWriteMemory,
                        Description = "Frida write_memory",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""dataHex"": { ""type"": ""string"" } }, ""required"": [""address"", ""dataHex""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolCallFunction,
                        Description = "Frida call_function",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""returnType"": { ""type"": ""string"" }, ""argTypes"": { ""type"": ""array"", ""items"": { ""type"": ""string"" } }, ""argValues"": { ""type"": ""array"" } }, ""required"": [""address"", ""argTypes"", ""argValues""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookStart,
                        Description = "Frida hook_start (kalici hook)",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" }, ""export"": { ""type"": ""string"" }, ""maxArgs"": { ""type"": ""integer"" }, ""includeArgs"": { ""type"": ""boolean"" }, ""includeBacktrace"": { ""type"": ""boolean"" }, ""includeRetval"": { ""type"": ""boolean"" }, ""once"": { ""type"": ""boolean"" }, ""autoStop"": { ""type"": ""boolean"" }, ""stream"": { ""type"": ""boolean"" }, ""pollIntervalMs"": { ""type"": ""integer"" }, ""maxEvents"": { ""type"": ""integer"" } } }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookPoll,
                        Description = "Frida hook_poll (event oku)",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""hookId"": { ""type"": ""string"" }, ""maxEvents"": { ""type"": ""integer"" } }, ""required"": [""hookId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolHookStop,
                        Description = "Frida hook_stop",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""hookId"": { ""type"": ""string"" } }, ""required"": [""hookId""] }"
                    },
                    new ToolInfo
                    {
                        Name = ToolSetBreakpoint,
                        Description = "Frida set_breakpoint (hook tabanli)",
                        InputSchemaJson = @"{ ""type"": ""object"", ""properties"": { ""pid"": { ""type"": ""integer"" }, ""sessionId"": { ""type"": ""string"" }, ""address"": { ""type"": ""string"" }, ""module"": { ""type"": ""string"" }, ""export"": { ""type"": ""string"" }, ""maxArgs"": { ""type"": ""integer"" }, ""includeArgs"": { ""type"": ""boolean"" }, ""includeBacktrace"": { ""type"": ""boolean"" }, ""once"": { ""type"": ""boolean"" }, ""stream"": { ""type"": ""boolean"" }, ""pollIntervalMs"": { ""type"": ""integer"" }, ""maxEvents"": { ""type"": ""integer"" } } }"
                    }
                }
            });

        public override async Task<InvokeToolReply> InvokeTool(InvokeToolRequest request, ServerCallContext context)
        {
            try
            {
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
                    case ToolHookStart:
                        return await HandleHookStartAsync(request.ArgsJson, false, context.CancellationToken);
                    case ToolHookPoll:
                        return await HandleHookPollAsync(request.ArgsJson);
                    case ToolHookStop:
                        return await HandleHookStopAsync(request.ArgsJson);
                    case ToolSetBreakpoint:
                        return await HandleHookStartAsync(request.ArgsJson, true, context.CancellationToken);
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

            var data = await _cli.ReadStringAsync(pid, addressText, maxLength, encoding, cancellationToken);
            return new InvokeToolReply { ResultJson = BuildTextContent(BuildPayload(data)) };
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

                targetExpr = $"Module.getExportByName({moduleExpr}, {JsonSerializer.Serialize(exportName)})";
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
            builder.AppendLine("    function safeToString(value){ try { return value.toString(); } catch (e) { return '<err>'; } }");
            builder.AppendLine("    function buildArgs(args){");
            builder.AppendLine("      if (!includeArgs || maxArgs <= 0) return [];");
            builder.AppendLine("      var list = [];");
            builder.AppendLine("      var count = Math.min(maxArgs, args.length);");
            builder.AppendLine("      for (var i = 0; i < count; i++) {");
            builder.AppendLine("        try { list.push(args[i].toString()); } catch (e) { list.push('<err>'); }");
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

        private static string BuildPayload(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Undefined)
                return "{}";

            return element.GetRawText();
        }

        private sealed record ContentItem(string type, string text);
    }
}
