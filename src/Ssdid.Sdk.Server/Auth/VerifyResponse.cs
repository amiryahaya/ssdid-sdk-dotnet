using System.Text.Json;

namespace Ssdid.Sdk.Server.Auth;

public record VerifyResponse(JsonElement Credential, string Did);
