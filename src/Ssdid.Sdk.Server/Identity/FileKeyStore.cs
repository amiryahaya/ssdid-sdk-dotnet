using System.Text.Json;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.Encoding;

namespace Ssdid.Sdk.Server.Identity;

/// <summary>
/// Stores server identity as a plaintext JSON file.
/// Suitable for development only — private key is stored unencrypted on disk.
/// </summary>
public class FileKeyStore : IKeyStore
{
    private readonly string _path;
    private SsdidIdentity? _cached;

    public FileKeyStore(string path)
    {
        _path = path;
    }

    public SsdidIdentity LoadOrCreate(string algorithmType, CryptoProviderFactory cryptoFactory)
    {
        if (_cached is not null) return _cached;
        _cached = SsdidIdentity.LoadOrCreate(_path, algorithmType, cryptoFactory);
        return _cached;
    }

    public byte[] Sign(byte[] message, string algorithmType, CryptoProviderFactory cryptoFactory)
    {
        var identity = LoadOrCreate(algorithmType, cryptoFactory);
        return cryptoFactory.Sign(identity.AlgorithmType, message, identity.PrivateKey);
    }
}
