using System.Security.Cryptography;
using System.Text;

namespace Ssdid.Sdk.Server.Session;

/// <summary>
/// Computes a device fingerprint from request metadata.
/// The fingerprint is a SHA-256 hash of User-Agent + X-SSDID-Device-ID header.
/// </summary>
public static class DeviceFingerprint
{
    public const string DeviceIdHeader = "X-SSDID-Device-ID";

    public static string Compute(string? userAgent, string? deviceId)
    {
        var input = $"{userAgent ?? "unknown"}|{deviceId ?? "none"}";
        var hash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input));
        return Convert.ToHexStringLower(hash);
    }
}
