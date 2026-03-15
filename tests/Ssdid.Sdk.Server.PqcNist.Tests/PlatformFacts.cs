namespace Ssdid.Sdk.Server.PqcNist.Tests;

/// <summary>
/// Skip helpers for platform-dependent crypto tests.
/// ML-DSA and SLH-DSA use BouncyCastle (cross-platform, always available).
/// </summary>
public static class PlatformFacts
{
    public static void SkipIfMlDsaUnsupported()
    {
        // BouncyCastle ML-DSA is always available — no skip needed
    }

    public static void SkipIfSlhDsaUnsupported()
    {
        // BouncyCastle SLH-DSA is always available — no skip needed
    }
}
