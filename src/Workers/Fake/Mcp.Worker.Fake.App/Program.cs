using Mcp.Workers.Protocol;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(5051, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http2;
    });
});

// gRPC
builder.Services.AddGrpc();

var app = builder.Build();

app.MapGrpcService<FakeWorkerService>();
app.MapGet("/", () => "FakeWorker is running");

app.Run("http://localhost:5051");

// --- gRPC Service (şimdilik inline; sonra ayrı dosya/proje olacak)
public class FakeWorkerService : Worker.WorkerBase
{
    public override Task<ListToolsReply> ListTools(ListToolsRequest request, Grpc.Core.ServerCallContext context)
        => Task.FromResult(new ListToolsReply
        {
            Tools =
            {
                new ToolInfo
                {
                    Name = "tools.ping",
                    Description = "Returns pong",
                    InputSchemaJson = @"{ ""type"": ""object"", ""properties"": {}, ""additionalProperties"": false }"
                }
            }
        });

    public override Task<InvokeToolReply> InvokeTool(InvokeToolRequest request, Grpc.Core.ServerCallContext context)
    {
        if (request.Name != "tools.ping")
            return Task.FromResult(new InvokeToolReply { Error = $"Unknown tool: {request.Name}" });

        return Task.FromResult(new InvokeToolReply
        {
            ResultJson = @"[{ ""type"": ""text"", ""text"": ""pong"" }]"
        });
    }
}
