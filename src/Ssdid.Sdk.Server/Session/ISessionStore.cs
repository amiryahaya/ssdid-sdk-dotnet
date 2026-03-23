namespace Ssdid.Sdk.Server.Session;

/// <summary>
/// Returned by <see cref="ISessionStore.ConsumeChallenge"/> with the original challenge payload.
/// </summary>
public record ChallengeEntry(string Challenge, string KeyId, DateTimeOffset CreatedAt, string? Domain = null);

/// <summary>
/// Manages authentication challenges and session lifecycle.
/// </summary>
public interface ISessionStore
{
    void CreateChallenge(string did, string purpose, string challenge, string keyId, string? domain = null);
    ChallengeEntry? ConsumeChallenge(string did, string purpose);
    string? CreateSession(string did, string? deviceFingerprint = null);
    string? GetSession(string token);
    string? GetSessionDeviceFingerprint(string token);
    void DeleteSession(string token);

    /// <summary>
    /// Invalidate all sessions for a given DID (used during recovery DID migration).
    /// Both <see cref="InMemory.InMemorySessionStore"/> and <see cref="Redis.RedisSessionStore"/> store the session value
    /// as a plain string and compare with <see cref="StringComparison.Ordinal"/>, so this method
    /// works equally well with DID strings and UUID strings (e.g. <c>Account.Id.ToString()</c>).
    /// </summary>
    void InvalidateSessionsForDid(string did);

    /// <summary>Alias for <see cref="InvalidateSessionsForDid"/> — works for any session value (DID or Account.Id).</summary>
    void InvalidateSessionsForAccount(Guid accountId) => InvalidateSessionsForDid(accountId.ToString());

    int ActiveSessionCount { get; }
    int ActiveChallengeCount { get; }
}
