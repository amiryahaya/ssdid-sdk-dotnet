using Ssdid.Sdk.Server.Crypto;

namespace Ssdid.Sdk.Server.Identity;

/// <summary>
/// Abstraction for server identity key storage and signing.
/// The private key never needs to leave the key store — all signing
/// happens through <see cref="Sign"/>.
///
/// Implementations:
/// - <see cref="FileKeyStore"/> — plaintext JSON file (development only)
/// - <see cref="SecretKeyStore"/> — reads from container secrets (Podman/Docker/K8s)
/// - Future: PKCS#11 HSM via Ssdid.Sdk.Server.Pkcs11 package
/// </summary>
public interface IKeyStore
{
    /// <summary>
    /// Load or create a server identity. If the identity doesn't exist,
    /// generate a new keypair and persist it.
    /// </summary>
    SsdidIdentity LoadOrCreate(string algorithmType, CryptoProviderFactory cryptoFactory);

    /// <summary>
    /// Sign a message using the stored private key.
    /// The private key may never leave the key store (e.g., HSM).
    /// </summary>
    byte[] Sign(byte[] message, string algorithmType, CryptoProviderFactory cryptoFactory);
}
