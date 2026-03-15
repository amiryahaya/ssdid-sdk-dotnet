namespace Ssdid.Sdk.Server.Auth;

public record RegisterResponse(string Challenge, string ServerDid, string ServerKeyId, string ServerSignature);
