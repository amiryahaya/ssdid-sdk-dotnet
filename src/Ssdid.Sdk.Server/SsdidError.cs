namespace Ssdid.Sdk.Server;

public record SsdidError(string Code, string Message, int? HttpStatus = null)
{
    public static SsdidError BadRequest(string message) => new("bad_request", message, 400);
    public static SsdidError NotFound(string message) => new("not_found", message, 404);
    public static SsdidError Unauthorized(string message) => new("unauthorized", message, 401);
    public static SsdidError Forbidden(string message) => new("forbidden", message, 403);
    public static SsdidError Conflict(string message) => new("conflict", message, 409);
    public static SsdidError Internal(string message) => new("internal", message, 500);
    public static SsdidError ServiceUnavailable(string message) => new("service_unavailable", message, 503);
}
