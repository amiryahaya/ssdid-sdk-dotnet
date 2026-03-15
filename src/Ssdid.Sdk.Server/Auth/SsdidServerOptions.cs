namespace Ssdid.Sdk.Server.Auth;

/// <summary>
/// Configuration options for SSDID server authentication.
/// </summary>
public class SsdidServerOptions
{
    /// <summary>
    /// Previous server identities for key rotation support.
    /// Keys issued by rotated identities remain valid until their credential expires.
    /// </summary>
    public List<PreviousIdentityEntry> PreviousIdentities { get; set; } = [];
}

/// <summary>
/// A previously-used server identity whose issued credentials should still be trusted.
/// </summary>
public class PreviousIdentityEntry
{
    public string Did { get; set; } = default!;
    public string PublicKey { get; set; } = default!;
    public string AlgorithmType { get; set; } = "Ed25519VerificationKey2020";
    public string? KeyId { get; set; }
}
