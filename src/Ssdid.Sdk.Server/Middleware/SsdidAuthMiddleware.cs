using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Ssdid.Sdk.Server.Session;

namespace Ssdid.Sdk.Server.Middleware;

/// <summary>
/// ASP.NET Core middleware that validates Bearer tokens against the SSDID session store.
/// Populates HttpContext.Items["SsdidUser"] with the authenticated user.
/// </summary>
public class SsdidAuthMiddleware(RequestDelegate next, ILogger<SsdidAuthMiddleware> logger)
{
    public const string UserKey = "SsdidUser";

    public async Task InvokeAsync(HttpContext context, ISessionStore sessionStore)
    {
        var auth = context.Request.Headers.Authorization.FirstOrDefault();
        if (auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth["Bearer ".Length..].Trim();
            var did = sessionStore.GetSession(token);
            if (did is not null)
            {
                context.Items[UserKey] = new SsdidUser(did, token);
            }
            else
            {
                logger.LogDebug("Invalid or expired session token");
            }
        }

        await next(context);
    }
}
