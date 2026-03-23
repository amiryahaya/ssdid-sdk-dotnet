using System.Text.Json;

namespace Ssdid.Sdk.Server.Registry;

/// <summary>
/// Abstraction for registry operations. Enables mocking in tests and alternative implementations.
/// </summary>
public interface IRegistryClient
{
    Task<JsonElement?> ResolveDid(string did);
    Task<(bool Success, string? Error)> RegisterDidDocument(object didDocument, object proof);

    static (byte[] PublicKey, string AlgorithmType)? ExtractPublicKey(JsonElement didDocument, string keyId)
        => RegistryClient.ExtractPublicKey(didDocument, keyId);
}
