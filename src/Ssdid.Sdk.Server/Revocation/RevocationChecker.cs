using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Ssdid.Sdk.Server.Revocation;

/// <summary>
/// Checks credential revocation status against W3C Bitstring Status Lists.
/// </summary>
public class RevocationChecker(IStatusListFetcher fetcher, ILogger<RevocationChecker> logger)
{
    /// <summary>
    /// Check if a credential has been revoked.
    /// Returns RevocationStatus.Valid if no credentialStatus field exists.
    /// Returns RevocationStatus.Unknown if the status list cannot be fetched.
    /// </summary>
    public async Task<RevocationStatus> CheckAsync(JsonElement credential)
    {
        if (!credential.TryGetProperty("credentialStatus", out var status))
            return RevocationStatus.Valid;

        if (!status.TryGetProperty("statusListIndex", out var indexEl) ||
            !status.TryGetProperty("statusListCredential", out var urlEl))
        {
            logger.LogWarning("Credential has credentialStatus but missing required fields");
            return RevocationStatus.Unknown;
        }

        var indexStr = indexEl.GetString() ?? indexEl.ToString();
        if (!int.TryParse(indexStr, out var index))
        {
            logger.LogWarning("Invalid statusListIndex: {Index}", indexStr);
            return RevocationStatus.Unknown;
        }

        var url = urlEl.GetString();
        if (url is null)
            return RevocationStatus.Unknown;

        var statusList = await fetcher.FetchAsync(url);
        if (statusList is null)
        {
            logger.LogWarning("Could not fetch status list from {Url}", url);
            return RevocationStatus.Unknown;
        }

        try
        {
            return BitstringParser.IsRevoked(statusList.EncodedList, index)
                ? RevocationStatus.Revoked
                : RevocationStatus.Valid;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error checking revocation at index {Index}", index);
            return RevocationStatus.Unknown;
        }
    }
}
