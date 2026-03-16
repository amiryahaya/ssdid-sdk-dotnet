using System.Text.Json;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.Encoding;

namespace Ssdid.Sdk.Server.Identity;

/// <summary>
/// Reads server identity from container secrets (Podman/Docker/Kubernetes).
/// The secret file is mounted at a path like /run/secrets/ssdid-identity
/// and contains the same JSON format as FileKeyStore.
///
/// If the secret file doesn't exist, falls back to creating a new identity
/// and writing it to the secret path (useful for first-run bootstrapping).
///
/// For Podman:
///   podman secret create ssdid-identity server-identity.json
///   podman run --secret ssdid-identity ...
///   # File appears at /run/secrets/ssdid-identity
///
/// For Docker Compose:
///   secrets:
///     ssdid-identity:
///       file: ./server-identity.json
///   services:
///     api:
///       secrets: [ssdid-identity]
///
/// For Kubernetes:
///   kubectl create secret generic ssdid-identity --from-file=server-identity.json
///   # Mount as volume at /run/secrets/ssdid-identity
///
/// Also supports reading from environment variables:
///   SSDID_IDENTITY_JSON='{"Did":"...","PrivateKey":"...",...}'
/// </summary>
public class SecretKeyStore : IKeyStore
{
    private readonly string? _secretPath;
    private readonly string? _envVarName;
    private SsdidIdentity? _cached;

    /// <summary>
    /// Create a SecretKeyStore that reads from a file path (container secret mount).
    /// </summary>
    public SecretKeyStore(string secretPath)
    {
        _secretPath = secretPath;
        _envVarName = null;
    }

    /// <summary>
    /// Create a SecretKeyStore that reads from an environment variable.
    /// </summary>
    public static SecretKeyStore FromEnvironment(string envVarName = "SSDID_IDENTITY_JSON")
    {
        return new SecretKeyStore(secretPath: null, envVarName: envVarName);
    }

    private SecretKeyStore(string? secretPath, string? envVarName)
    {
        _secretPath = secretPath;
        _envVarName = envVarName;
    }

    public SsdidIdentity LoadOrCreate(string algorithmType, CryptoProviderFactory cryptoFactory)
    {
        if (_cached is not null) return _cached;

        string? json = null;

        // Try environment variable first
        if (!string.IsNullOrEmpty(_envVarName))
        {
            json = Environment.GetEnvironmentVariable(_envVarName);
        }

        // Try secret file
        if (string.IsNullOrEmpty(json) && !string.IsNullOrEmpty(_secretPath) && File.Exists(_secretPath))
        {
            json = File.ReadAllText(_secretPath);
        }

        if (!string.IsNullOrEmpty(json))
        {
            var data = JsonSerializer.Deserialize<IdentityData>(json)!;
            var loadedAlgorithm = data.AlgorithmType ?? "Ed25519VerificationKey2020";
            _cached = new SsdidIdentity
            {
                Did = data.Did,
                KeyId = data.KeyId,
                PublicKey = SsdidEncoding.Base64UrlDecode(data.PublicKey),
                PrivateKey = SsdidEncoding.Base64UrlDecode(data.PrivateKey),
                AlgorithmType = loadedAlgorithm,
                AlgorithmMismatch = loadedAlgorithm != algorithmType,
            };
            _cached.SetCryptoFactory(cryptoFactory);
            return _cached;
        }

        // No secret found — create new identity (first-run bootstrap)
        // Write to secret path if available so it persists
        var identity = SsdidIdentity.Create(algorithmType, cryptoFactory);

        if (!string.IsNullOrEmpty(_secretPath))
        {
            var dir = Path.GetDirectoryName(_secretPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var saveData = new IdentityData(
                identity.Did, identity.KeyId,
                SsdidEncoding.Base64UrlEncode(identity.PublicKey),
                SsdidEncoding.Base64UrlEncode(identity.PrivateKey),
                identity.AlgorithmType);
            File.WriteAllText(_secretPath, JsonSerializer.Serialize(saveData,
                new JsonSerializerOptions { WriteIndented = true }));

            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(_secretPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        _cached = identity;
        return _cached;
    }

    public byte[] Sign(byte[] message, string algorithmType, CryptoProviderFactory cryptoFactory)
    {
        var identity = LoadOrCreate(algorithmType, cryptoFactory);
        return cryptoFactory.Sign(identity.AlgorithmType, message, identity.PrivateKey);
    }

    private record IdentityData(string Did, string KeyId, string PublicKey, string PrivateKey, string? AlgorithmType = null);
}
