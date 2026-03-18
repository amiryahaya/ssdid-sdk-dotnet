namespace Ssdid.Sdk.Server;

/// <summary>
/// Utilities for SSDID DID format validation.
/// DID format: did:ssdid:{base64url-encoded-128-bit-random}
/// </summary>
public static class SsdidDid
{
    private const string Prefix = "did:ssdid:";
    private const int MinSuffixLength = 22;  // 128-bit entropy in base64url
    private const int MaxSuffixLength = 128; // DoS prevention

    /// <summary>
    /// Validates that a string is a well-formed SSDID DID.
    /// </summary>
    public static bool IsValid(string? did)
    {
        if (string.IsNullOrEmpty(did) || !did.StartsWith(Prefix))
            return false;

        var suffix = did.AsSpan(Prefix.Length);
        if (suffix.Length < MinSuffixLength || suffix.Length > MaxSuffixLength)
            return false;

        // ASCII-only base64url characters
        foreach (var c in suffix)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_')
                return false;
        }

        return true;
    }

    /// <summary>
    /// Validates and returns the DID, or throws ArgumentException.
    /// </summary>
    public static string Validate(string? did)
    {
        if (!IsValid(did))
            throw new ArgumentException(
                $"Invalid SSDID DID format. Must be '{Prefix}' followed by 22-128 base64url characters.", nameof(did));
        return did!;
    }
}
