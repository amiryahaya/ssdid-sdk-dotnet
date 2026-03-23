using System.Text.Json;

namespace Ssdid.Sdk.Server.Credentials;

/// <summary>
/// Issues Verifiable Credentials. The default implementation issues SsdidRegistrationCredential.
/// Consumers can register custom implementations for domain-specific credential types.
/// </summary>
public interface ICredentialIssuer
{
    string CredentialType { get; }
    JsonElement Issue(CredentialRequest request);
}

public record CredentialRequest(
    string SubjectDid,
    string IssuerDid,
    string IssuerKeyId,
    string AlgorithmType,
    byte[] PrivateKey,
    string ServiceId,
    string? ServiceName = null,
    string? ServiceUrl = null,
    Dictionary<string, string>? AdditionalClaims = null);
