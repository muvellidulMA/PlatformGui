using Mcp.Gateway.App.Options;
using Microsoft.Extensions.Options;

namespace Mcp.Gateway.App.Services;

public sealed class GatewayAuth
{
    private readonly string? _token;

    public GatewayAuth(IOptions<GatewayOptions> options)
    {
        _token = options.Value.AuthToken;
    }

    public bool IsAuthorized(HttpContext context)
    {
        if (string.IsNullOrWhiteSpace(_token))
            return true;

        var header = context.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var value = header.Substring("Bearer ".Length).Trim();
            if (string.Equals(value, _token, StringComparison.Ordinal))
                return true;
        }

        if (context.Request.Headers.TryGetValue("X-Api-Key", out var apiKey) &&
            string.Equals(apiKey.ToString(), _token, StringComparison.Ordinal))
            return true;

        var queryToken = GetQueryToken(context);
        return string.Equals(queryToken, _token, StringComparison.Ordinal);
    }

    public string? GetQueryToken(HttpContext context)
    {
        var token = context.Request.Query["token"].ToString();
        if (!string.IsNullOrWhiteSpace(token))
            return token;

        token = context.Request.Query["access_token"].ToString();
        return string.IsNullOrWhiteSpace(token) ? null : token;
    }
}
