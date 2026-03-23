using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Ssdid.Sdk.Server.Revocation;

/// <summary>
/// Fetches status lists via HTTP with in-memory caching (5 minute TTL).
/// </summary>
public class HttpStatusListFetcher(HttpClient httpClient, ILogger<HttpStatusListFetcher> logger) : IStatusListFetcher
{
    private readonly Dictionary<string, (StatusListResult Result, DateTime ExpiresAt)> _cache = new();
    private readonly object _lock = new();
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

    public async Task<StatusListResult?> FetchAsync(string statusListUrl)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(statusListUrl, out var cached) && cached.ExpiresAt > DateTime.UtcNow)
                return cached.Result;
        }

        try
        {
            var response = await httpClient.GetAsync(statusListUrl);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Status list fetch failed: {Status} for {Url}", response.StatusCode, statusListUrl);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var encodedList = root.GetProperty("credentialSubject").GetProperty("encodedList").GetString();
            var statusPurpose = root.GetProperty("credentialSubject").GetProperty("statusPurpose").GetString();

            if (encodedList is null || statusPurpose is null) return null;

            var result = new StatusListResult(encodedList, statusPurpose);
            lock (_lock)
            {
                _cache[statusListUrl] = (result, DateTime.UtcNow.Add(CacheTtl));
            }
            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error fetching status list from {Url}", statusListUrl);
            return null;
        }
    }
}
