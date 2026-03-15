using Ssdid.Sdk.Server.KazSign.Providers;

namespace Ssdid.Sdk.Server.KazSign.Tests;

/// <summary>
/// Skip helpers for platform-dependent crypto tests.
/// KAZ-Sign depends on a native library that may not be available.
/// </summary>
public static class PlatformFacts
{
    public static bool IsKazSignSupported { get; } = CheckKazSignSupported();

    private static bool CheckKazSignSupported()
    {
        try
        {
            using var provider = new KazSignProvider();
            var (pub, priv) = provider.GenerateKeyPair(null);
            // Also verify signing works (not just keygen)
            var sig = provider.Sign(System.Text.Encoding.UTF8.GetBytes("test"), priv, null);
            return provider.Verify(System.Text.Encoding.UTF8.GetBytes("test"), sig, pub, null);
        }
        catch
        {
            return false;
        }
    }

    public static void SkipIfKazSignUnsupported()
    {
        if (!IsKazSignSupported)
            throw new SkipException("libkazsign native library not available or not functional");
    }
}

/// <summary>
/// Exception that signals xUnit to skip a test.
/// Compatible with xUnit v2 via the $XunitDynamicSkip message prefix.
/// </summary>
public class SkipException : Exception
{
    public SkipException(string reason) : base($"$XunitDynamicSkip${reason}") { }
}
