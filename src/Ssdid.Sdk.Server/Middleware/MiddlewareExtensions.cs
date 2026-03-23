using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Ssdid.Sdk.Server.Middleware;

public static class MiddlewareExtensions
{
    /// <summary>
    /// Adds SSDID session-based authentication middleware to the pipeline.
    /// Validates Bearer tokens and populates HttpContext.Items with the authenticated user.
    /// </summary>
    public static IApplicationBuilder UseSsdidAuth(this IApplicationBuilder app)
        => app.UseMiddleware<SsdidAuthMiddleware>();

    /// <summary>
    /// Gets the authenticated SSDID user from the current request, or null if unauthenticated.
    /// </summary>
    public static ISsdidUser? GetSsdidUser(this HttpContext context)
        => context.Items.TryGetValue(SsdidAuthMiddleware.UserKey, out var user)
            ? user as ISsdidUser
            : null;
}
