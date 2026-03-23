namespace Ssdid.Sdk.Server.Middleware;

/// <summary>
/// Represents an authenticated SSDID user extracted from the session token.
/// </summary>
public interface ISsdidUser
{
    string Did { get; }
    string SessionId { get; }
}

internal record SsdidUser(string Did, string SessionId) : ISsdidUser;
