namespace Ssdid.Sdk.Server.Audit;

/// <summary>
/// Receives audit events from the SSDID auth pipeline.
/// Implement this interface to integrate with your audit backend.
/// </summary>
public interface ISsdidAuditSink
{
    Task OnEventAsync(SsdidAuditEvent evt);
}

public record SsdidAuditEvent(
    SsdidAuditEventType Type,
    string Did,
    DateTimeOffset Timestamp,
    Dictionary<string, string>? Details = null);

public enum SsdidAuditEventType
{
    DidRegistered,
    ChallengeIssued,
    CredentialIssued,
    CredentialVerified,
    SessionCreated,
    SessionRevoked,
    CredentialRevoked
}

/// <summary>No-op audit sink (default). Replace via DI for production.</summary>
public class NullAuditSink : ISsdidAuditSink
{
    public Task OnEventAsync(SsdidAuditEvent evt) => Task.CompletedTask;
}
