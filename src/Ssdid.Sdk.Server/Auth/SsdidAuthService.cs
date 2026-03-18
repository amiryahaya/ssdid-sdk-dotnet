using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.Encoding;
using Ssdid.Sdk.Server.Identity;
using Ssdid.Sdk.Server.Registry;
using Ssdid.Sdk.Server.Session;

namespace Ssdid.Sdk.Server.Auth;

public class SsdidAuthService
{
    private readonly SsdidIdentity _identity;
    private readonly ISessionStore _sessionStore;
    private readonly RegistryClient _registryClient;
    private readonly CryptoProviderFactory _cryptoFactory;
    private readonly ILogger<SsdidAuthService> _logger;
    private readonly IReadOnlyDictionary<string, (byte[] PublicKey, string AlgorithmType, string KeyId)> _trustedKeys;
    private readonly string _serviceId;
    private readonly string _serviceName;
    private readonly string _serviceUrl;

    private static readonly JsonSerializerOptions VcSerializerOptions = new() { WriteIndented = false };

    public SsdidAuthService(
        SsdidIdentity identity,
        ISessionStore sessionStore,
        RegistryClient registryClient,
        CryptoProviderFactory cryptoFactory,
        IOptions<SsdidServerOptions> options,
        ILogger<SsdidAuthService> logger)
    {
        _identity = identity;
        _sessionStore = sessionStore;
        _registryClient = registryClient;
        _cryptoFactory = cryptoFactory;
        _logger = logger;
        _trustedKeys = BuildTrustedKeys(identity, options.Value);
        _serviceId = options.Value.ServiceId;
        _serviceName = options.Value.ServiceName;
        _serviceUrl = options.Value.ServiceUrl;
    }

    private static IReadOnlyDictionary<string, (byte[] PublicKey, string AlgorithmType, string KeyId)> BuildTrustedKeys(
        SsdidIdentity identity, SsdidServerOptions options)
    {
        var keys = new Dictionary<string, (byte[] PublicKey, string AlgorithmType, string KeyId)>
        {
            [identity.Did] = (identity.PublicKey, identity.AlgorithmType, identity.KeyId)
        };
        foreach (var entry in options.PreviousIdentities)
        {
            var keyId = entry.KeyId ?? $"{entry.Did}#key-1";
            keys[entry.Did] = (SsdidEncoding.Base64UrlDecode(entry.PublicKey), entry.AlgorithmType, keyId);
        }
        return keys.AsReadOnly();
    }

    public async Task<Result<RegisterResponse>> HandleRegister(string clientDid, string clientKeyId)
    {
        if (!SsdidDid.IsValid(clientDid))
            return SsdidError.BadRequest("Invalid DID format");

        var didDoc = await _registryClient.ResolveDid(clientDid);
        if (didDoc is null)
        {
            _logger.LogWarning("Registration failed: DID not found {Did}", clientDid);
            return SsdidError.NotFound("DID not found in registry");
        }

        var challenge = SsdidEncoding.GenerateChallenge();
        var serverSignature = _identity.SignChallenge(challenge);
        _sessionStore.CreateChallenge(clientDid, "registration", challenge, clientKeyId);

        return new RegisterResponse(challenge, _identity.Did, _identity.KeyId, serverSignature);
    }

    public async Task<Result<VerifyResponse>> HandleVerifyResponse(string clientDid, string clientKeyId, string signedChallenge)
    {
        if (!SsdidDid.IsValid(clientDid))
            return SsdidError.BadRequest("Invalid DID format");

        var entry = _sessionStore.ConsumeChallenge(clientDid, "registration");
        if (entry is null)
        {
            _logger.LogWarning("Verify failed: no challenge found for {Did}", clientDid);
            return SsdidError.Unauthorized("No pending challenge found or challenge expired");
        }

        if (entry.KeyId != clientKeyId)
        {
            _logger.LogWarning("Verify failed: key ID mismatch for {Did}", clientDid);
            return SsdidError.Unauthorized("Key ID does not match the pending challenge");
        }

        var didDoc = await _registryClient.ResolveDid(clientDid);
        if (didDoc is null)
            return SsdidError.NotFound("DID not found in registry");

        var extracted = RegistryClient.ExtractPublicKey(didDoc.Value, clientKeyId);
        if (extracted is null)
        {
            _logger.LogWarning("Verify failed: public key not found for {KeyId}", clientKeyId);
            return SsdidError.NotFound("Public key not found in DID Document");
        }

        var (publicKey, algorithmType) = extracted.Value;
        var signatureBytes = SsdidEncoding.MultibaseDecode(signedChallenge);
        var challengeBytes = System.Text.Encoding.UTF8.GetBytes(entry.Challenge);

        if (!_cryptoFactory.Verify(algorithmType, challengeBytes, signatureBytes, publicKey))
        {
            _logger.LogWarning("Verify failed: invalid signature for {Did}", clientDid);
            return SsdidError.Unauthorized("Signature verification failed");
        }

        var credential = IssueCredential(clientDid);
        _logger.LogInformation("Registration verified for {Did}", clientDid);

        return new VerifyResponse(credential, clientDid);
    }

    public Result<string> VerifyCredential(JsonElement credential)
    {
        if (!VerifyCredentialOffline(credential))
        {
            _logger.LogWarning("Authentication failed: invalid credential");
            return SsdidError.Unauthorized("Invalid or expired credential");
        }

        var subjectDid = credential
            .GetProperty("credentialSubject")
            .GetProperty("id")
            .GetString();

        if (subjectDid is null)
            return SsdidError.Unauthorized("Credential missing subject DID");

        return subjectDid;
    }

    public Result<AuthenticateResponse> CreateAuthenticatedSession(string did)
    {
        var sessionToken = _sessionStore.CreateSession(did);
        if (sessionToken is null)
        {
            _logger.LogWarning("Authentication failed: session limit reached");
            return SsdidError.ServiceUnavailable("Session limit reached, try again later");
        }

        var serverSignature = _identity.SignChallenge(sessionToken);
        _logger.LogInformation("Authenticated {Did}", did);

        return new AuthenticateResponse(sessionToken, did, _identity.Did, _identity.KeyId, serverSignature);
    }

    public void RevokeSession(string token) => _sessionStore.DeleteSession(token);

    private Dictionary<string, object> BuildCredentialSubject(string subjectDid, string issuanceDate)
    {
        var subject = new Dictionary<string, object>
        {
            ["id"] = subjectDid,
            ["service"] = _serviceId,
            ["registeredAt"] = issuanceDate
        };

        if (!string.IsNullOrEmpty(_serviceName))
            subject["serviceName"] = _serviceName;
        if (!string.IsNullOrEmpty(_serviceUrl))
            subject["serviceUrl"] = _serviceUrl;

        return subject;
    }

    private static string BuildSigningInput(
        string vcId, string issuer, string issuanceDate,
        string expirationDate, string subjectDid, string service)
    {
        static string Lp(string s) => $"{s.Length}:{s}";
        return $"{Lp(vcId)};{Lp(issuer)};{Lp(issuanceDate)};{Lp(expirationDate)};{Lp(subjectDid)};{Lp(service)}";
    }

    private JsonElement IssueCredential(string subjectDid)
    {
        var now = DateTimeOffset.UtcNow;
        var vcId = $"urn:uuid:{Guid.NewGuid()}";
        var issuanceDate = now.ToString("o");
        var expirationDate = now.AddDays(30).ToString("o");

        var signingInput = BuildSigningInput(
            vcId, _identity.Did, issuanceDate, expirationDate, subjectDid, _serviceId);
        var proofBytes = _cryptoFactory.Sign(
            _identity.AlgorithmType,
            System.Text.Encoding.UTF8.GetBytes(signingInput),
            _identity.PrivateKey);

        var proofType = CryptoProviderFactory.GetProofType(_identity.AlgorithmType);

        // Use Dictionary to preserve "@context" key (C# anonymous @context serializes as "context")
        var vc = new Dictionary<string, object>
        {
            ["@context"] = new[] { "https://www.w3.org/2018/credentials/v1" },
            ["id"] = vcId,
            ["type"] = new[] { "VerifiableCredential", "SsdidRegistrationCredential" },
            ["issuer"] = _identity.Did,
            ["issuanceDate"] = issuanceDate,
            ["expirationDate"] = expirationDate,
            ["credentialSubject"] = BuildCredentialSubject(subjectDid, issuanceDate),
            ["proof"] = new Dictionary<string, object>
            {
                ["type"] = proofType!,
                ["created"] = now.ToString("o"),
                ["verificationMethod"] = _identity.KeyId,
                ["proofPurpose"] = "assertionMethod",
                ["proofValue"] = SsdidEncoding.MultibaseEncode(proofBytes)
            }
        };

        return JsonSerializer.SerializeToElement(vc, VcSerializerOptions);
    }

    private bool VerifyCredentialOffline(JsonElement credential)
    {
        try
        {
            var issuer = credential.GetProperty("issuer").GetString();
            if (issuer is null || !_trustedKeys.TryGetValue(issuer, out var trustedKey))
            {
                _logger.LogWarning("VC verification failed: untrusted issuer {Issuer}", issuer);
                return false;
            }

            // Validate VC type includes SsdidRegistrationCredential
            if (!credential.TryGetProperty("type", out var typeArr) ||
                typeArr.ValueKind != JsonValueKind.Array)
            {
                _logger.LogWarning("VC verification failed: missing or invalid type array");
                return false;
            }

            var hasCredentialType = false;
            foreach (var t in typeArr.EnumerateArray())
            {
                if (t.GetString() == "SsdidRegistrationCredential")
                {
                    hasCredentialType = true;
                    break;
                }
            }

            if (!hasCredentialType)
            {
                _logger.LogWarning("VC verification failed: missing SsdidRegistrationCredential type");
                return false;
            }

            if (!credential.TryGetProperty("id", out var idEl) ||
                !credential.TryGetProperty("issuanceDate", out var issuanceDateEl) ||
                !credential.TryGetProperty("expirationDate", out var expirationDateEl) ||
                !credential.TryGetProperty("credentialSubject", out var subject) ||
                !subject.TryGetProperty("id", out var subjectDidEl) ||
                !subject.TryGetProperty("service", out var serviceEl) ||
                !credential.TryGetProperty("proof", out var proof) ||
                !proof.TryGetProperty("proofValue", out var proofValueEl))
            {
                _logger.LogWarning("VC verification failed: missing required properties");
                return false;
            }

            // Validate proof.proofPurpose
            if (!proof.TryGetProperty("proofPurpose", out var proofPurposeEl) ||
                proofPurposeEl.GetString() != "assertionMethod")
            {
                _logger.LogWarning("VC verification failed: invalid or missing proofPurpose");
                return false;
            }

            // Validate proof.verificationMethod matches trusted key
            if (!proof.TryGetProperty("verificationMethod", out var vmEl) ||
                vmEl.GetString() != trustedKey.KeyId)
            {
                _logger.LogWarning("VC verification failed: verificationMethod mismatch");
                return false;
            }

            var vcId = idEl.GetString();
            var issuanceDate = issuanceDateEl.GetString();
            var expirationDate = expirationDateEl.GetString();
            var subjectDid = subjectDidEl.GetString();
            var service = serviceEl.GetString();
            var proofValue = proofValueEl.GetString();

            if (vcId is null || issuanceDate is null || expirationDate is null ||
                subjectDid is null || service is null || proofValue is null)
            {
                _logger.LogWarning("VC verification failed: null property values");
                return false;
            }

            if (!DateTimeOffset.TryParse(expirationDate, null,
                    System.Globalization.DateTimeStyles.RoundtripKind, out var exp))
            {
                _logger.LogWarning("VC verification failed: unparseable expirationDate");
                return false;
            }

            if (exp < DateTimeOffset.UtcNow) return false;

            var signingInput = BuildSigningInput(vcId, issuer, issuanceDate, expirationDate, subjectDid, service);
            var sigBytes = SsdidEncoding.MultibaseDecode(proofValue);
            var msgBytes = System.Text.Encoding.UTF8.GetBytes(signingInput);

            return _cryptoFactory.Verify(trustedKey.AlgorithmType, msgBytes, sigBytes, trustedKey.PublicKey);
        }
        catch (Exception ex) when (ex is FormatException or ArgumentException or KeyNotFoundException)
        {
            _logger.LogWarning(ex, "VC verification failed: invalid date or encoding format");
            return false;
        }
    }
}
