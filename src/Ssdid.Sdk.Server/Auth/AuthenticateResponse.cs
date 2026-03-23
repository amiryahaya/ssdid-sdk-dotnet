namespace Ssdid.Sdk.Server.Auth;

public record AuthenticateResponse(string SessionToken, string Did, string ServerDid, string ServerKeyId, string ServerSignature, string ProtocolVersion = "1.0");
