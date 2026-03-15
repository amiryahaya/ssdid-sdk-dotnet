using Ssdid.Sdk.Server.Encoding;
using Ssdid.Sdk.Server.Session;

namespace Ssdid.Sdk.Server.Auth;

/// <summary>
/// Configuration options for SSDID server authentication.
/// </summary>
public class SsdidServerOptions
{
    /// <summary>
    /// File path for persisted server identity (DID + key pair).
    /// Default: "data/server-identity.json".
    /// </summary>
    public string IdentityPath { get; set; } = "data/server-identity.json";

    /// <summary>
    /// W3C verification method type for the server's key pair.
    /// Default: "Ed25519VerificationKey2020".
    /// </summary>
    public string Algorithm { get; set; } = "Ed25519VerificationKey2020";

    /// <summary>
    /// Base URL of the SSDID DID Registry.
    /// </summary>
    public string RegistryUrl { get; set; } = SsdidEncoding.DefaultRegistryUrl;

    /// <summary>
    /// Session and challenge TTL options.
    /// </summary>
    public SessionStoreOptions Sessions { get; set; } = new();

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
