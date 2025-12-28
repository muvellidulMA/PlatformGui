using Mcp.Worker.Frida.App.Options;
using Mcp.Worker.Frida.App.Services;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);

var fridaOptions = builder.Configuration.GetSection("Frida").Get<FridaOptions>() ?? new FridaOptions();
builder.Services.AddSingleton(fridaOptions);
builder.Services.AddSingleton<FridaSessionStore>();
builder.Services.AddSingleton<FridaCli>();
builder.Services.AddSingleton<FridaSessionManager>();
builder.Services.AddSingleton<FridaHookManager>();
builder.Services.AddSingleton<FridaScriptManager>();
builder.Services.AddSingleton<FridaToolPolicy>();

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(fridaOptions.Port, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http2;
    });
});

builder.Services.AddGrpc();

var app = builder.Build();

app.MapGrpcService<FridaWorkerService>();
app.MapGet("/", () => "FridaWorker is running");

app.Run();
