namespace Ssdid.Sdk.Server.Revocation;

/// <summary>
/// Fetches W3C Bitstring Status List credentials from a status list endpoint.
/// </summary>
public interface IStatusListFetcher
{
    Task<StatusListResult?> FetchAsync(string statusListUrl);
}

public record StatusListResult(string EncodedList, string StatusPurpose);
