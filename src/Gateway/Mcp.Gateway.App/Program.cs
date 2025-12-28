using Mcp.Gateway.App.Models;
using Mcp.Gateway.App.Options;
using Mcp.Gateway.App.Services;
using Mcp.Gateway.Core;
using Microsoft.Extensions.Options;

AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);

var builder = WebApplication.CreateBuilder(args);

var gatewayOptions = builder.Configuration.GetSection("Gateway").Get<GatewayOptions>() ?? new GatewayOptions();
var workerOptions = builder.Configuration.GetSection("Workers").Get<WorkerOptions[]>() ?? Array.Empty<WorkerOptions>();

var enableStdio = args.Any(arg => string.Equals(arg, "--stdio", StringComparison.OrdinalIgnoreCase));
var disableHttp = args.Any(arg => string.Equals(arg, "--no-http", StringComparison.OrdinalIgnoreCase));
var enableHttp = gatewayOptions.Http.Enabled && !disableHttp;

builder.Services.Configure<GatewayOptions>(builder.Configuration.GetSection("Gateway"));
builder.Services.AddSingleton<IReadOnlyList<WorkerOptions>>(workerOptions);

builder.Services.AddSingleton<GatewayAuth>();
builder.Services.AddSingleton<SseSessionManager>();
builder.Services.AddSingleton<HookStreamManager>();
builder.Services.AddSingleton<IMcpToolProvider, WorkerRouter>();
builder.Services.AddSingleton<IWorkerToolInvoker>(sp => (WorkerRouter)sp.GetRequiredService<IMcpToolProvider>());
builder.Services.AddSingleton(sp =>
{
    var options = sp.GetRequiredService<IOptions<GatewayOptions>>().Value;
    return new McpServerInfo(options.ServerName, options.ServerVersion, options.ProtocolVersion);
});
builder.Services.AddSingleton(sp =>
{
    var options = sp.GetRequiredService<IOptions<GatewayOptions>>().Value;
    var toolProvider = sp.GetRequiredService<IMcpToolProvider>();
    var serverInfo = sp.GetRequiredService<McpServerInfo>();
    return new McpMessageHandler(toolProvider, serverInfo, options.DefaultToolTimeoutMs);
});
builder.Services.AddSingleton<StdioMcpServer>();

if (enableHttp && !string.IsNullOrWhiteSpace(gatewayOptions.Http.Url))
    builder.WebHost.UseUrls(gatewayOptions.Http.Url);

var app = builder.Build();

if (enableHttp)
{
    app.MapGet("/", () => Results.Text("MCP Gateway aktif"));

    app.MapGet("/sse", async (HttpContext ctx, GatewayAuth auth, SseSessionManager sse) =>
    {
        if (!auth.IsAuthorized(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        ctx.Response.Headers["Content-Type"] = "text/event-stream";
        ctx.Response.Headers["Cache-Control"] = "no-cache";
        ctx.Response.Headers["X-Accel-Buffering"] = "no";
        ctx.Response.Headers["Connection"] = "keep-alive";

        var sessionId = sse.Register(ctx);
        var endpoint = sse.BuildEndpoint(sessionId, ctx);
        await sse.SendEventAsync(sessionId, "endpoint", endpoint, ctx.RequestAborted);
        await sse.WaitForDisconnectAsync(sessionId, ctx.RequestAborted);
    });

    app.MapPost("/sse", async (HttpContext ctx, GatewayAuth auth, McpMessageHandler handler) =>
    {
        if (!auth.IsAuthorized(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        using var reader = new StreamReader(ctx.Request.Body);
        var body = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsync("govde bos");
            return;
        }

        var responseJson = await handler.HandleAsync(body, null, ctx.RequestAborted);
        if (string.IsNullOrWhiteSpace(responseJson))
        {
            ctx.Response.StatusCode = StatusCodes.Status202Accepted;
            await ctx.Response.WriteAsync("Accepted");
            return;
        }

        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync(responseJson);
    });

    app.MapPost("/message", async (HttpContext ctx, GatewayAuth auth, SseSessionManager sse, McpMessageHandler handler) =>
    {
        if (!auth.IsAuthorized(ctx))
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        var sessionId = ctx.Request.Query["sessionId"].ToString();
        if (string.IsNullOrWhiteSpace(sessionId) || !sse.HasSession(sessionId))
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsync("sessionId gerekli");
            return;
        }

        using var reader = new StreamReader(ctx.Request.Body);
        var body = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(body))
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsync("govde bos");
            return;
        }

        var responseJson = await handler.HandleAsync(body, sessionId, ctx.RequestAborted);

        ctx.Response.StatusCode = StatusCodes.Status202Accepted;
        await ctx.Response.WriteAsync("Accepted");

        if (!string.IsNullOrWhiteSpace(responseJson))
            await sse.SendAsync(sessionId, responseJson, ctx.RequestAborted);
    });

    app.MapGet("/mcp/tools", async (HttpContext ctx, GatewayAuth auth, IMcpToolProvider toolProvider, CancellationToken ct) =>
    {
        if (!auth.IsAuthorized(ctx))
            return Results.Unauthorized();

        var tools = await toolProvider.ListToolsAsync(ct);
        var result = tools.Select(t => new ToolDto(t.Name, t.Description)).ToArray();
        return Results.Ok(result);
    });

    app.MapPost("/mcp/invoke", async (
        HttpContext ctx,
        GatewayAuth auth,
        IMcpToolProvider toolProvider,
        IOptions<GatewayOptions> options,
        InvokeRequestDto request,
        CancellationToken ct) =>
    {
        if (!auth.IsAuthorized(ctx))
            return Results.Unauthorized();

        if (string.IsNullOrWhiteSpace(request.Name))
            return Results.BadRequest("Name gerekli");

        var timeoutMs = options.Value.DefaultToolTimeoutMs;
        var result = await toolProvider.CallToolAsync(
            request.Name,
            request.ArgsJson ?? "{}",
            timeoutMs,
            null,
            ct);

        if (result.IsError)
            return Results.Problem(result.ErrorMessage ?? "Arac cagirma hatasi");

        return Results.Text(result.RawResultJson ?? "{}", "application/json");
    });
}

if (enableStdio)
{
    var stdioServer = app.Services.GetRequiredService<StdioMcpServer>();
    _ = Task.Run(() => stdioServer.RunAsync(app.Lifetime.ApplicationStopping));
}

if (enableHttp)
    await app.RunAsync();
else if (enableStdio)
    await Task.Delay(Timeout.Infinite, app.Lifetime.ApplicationStopping);
