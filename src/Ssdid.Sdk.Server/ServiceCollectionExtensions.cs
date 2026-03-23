using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Ssdid.Sdk.Server.Audit;
using Ssdid.Sdk.Server.Auth;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.Crypto.Providers;
using Ssdid.Sdk.Server.Identity;
using Ssdid.Sdk.Server.Registration;
using Ssdid.Sdk.Server.Registry;
using Ssdid.Sdk.Server.Revocation;
using Ssdid.Sdk.Server.Session;
using Ssdid.Sdk.Server.Session.InMemory;

namespace Ssdid.Sdk.Server;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSsdidServer(
        this IServiceCollection services,
        Action<SsdidServerOptions>? configure = null)
    {
        var options = new SsdidServerOptions();
        configure?.Invoke(options);

        // Options
        services.AddSingleton(Options.Create(options));
        services.AddSingleton(Options.Create(options.Sessions));

        // Crypto (Ed25519 + ECDSA built-in)
        services.AddSingleton<ICryptoProvider, Ed25519Provider>();
        services.AddSingleton<ICryptoProvider, EcdsaProvider>();
        services.AddSingleton<CryptoProviderFactory>();

        // Key Store (default: file-based, can be overridden before calling AddSsdidServer)
        if (!services.Any(d => d.ServiceType == typeof(IKeyStore)))
        {
            services.AddSingleton<IKeyStore>(new FileKeyStore(options.IdentityPath));
        }

        // Identity (loaded via key store)
        services.AddSingleton<SsdidIdentity>(sp =>
        {
            var cryptoFactory = sp.GetRequiredService<CryptoProviderFactory>();
            var keyStore = sp.GetRequiredService<IKeyStore>();
            var identity = keyStore.LoadOrCreate(options.Algorithm, cryptoFactory);
            identity.SetKeyStore(keyStore);
            return identity;
        });

        // Registry
        services.AddHttpClient<RegistryClient>(client =>
        {
            client.BaseAddress = new Uri(options.RegistryUrl);
            client.Timeout = TimeSpan.FromSeconds(15);
        });
        services.AddSingleton<IRegistryClient>(sp => sp.GetRequiredService<RegistryClient>());

        // Session (in-memory default)
        services.AddSingleton<InMemorySessionStore>();
        services.AddSingleton<ISessionStore>(sp => sp.GetRequiredService<InMemorySessionStore>());
        services.AddSingleton<ISseNotificationBus>(sp => sp.GetRequiredService<InMemorySessionStore>());

        // Audit (no-op default — consumers can replace via DI)
        if (!services.Any(d => d.ServiceType == typeof(ISsdidAuditSink)))
            services.AddSingleton<ISsdidAuditSink, NullAuditSink>();

        // Revocation
        services.AddHttpClient<HttpStatusListFetcher>();
        services.AddSingleton<IStatusListFetcher>(sp => sp.GetRequiredService<HttpStatusListFetcher>());
        services.AddSingleton<RevocationChecker>();

        // Auth
        services.AddScoped<SsdidAuthService>();

        // DID registration on startup
        services.AddHostedService<ServerRegistrationService>();

        return services;
    }

    /// <summary>
    /// Use container secrets (Podman/Docker/Kubernetes) for server identity storage.
    /// Call BEFORE AddSsdidServer().
    ///
    /// Example:
    ///   builder.Services.AddSsdidSecretKeyStore("/run/secrets/ssdid-identity");
    ///   builder.Services.AddSsdidServer(...);
    /// </summary>
    public static IServiceCollection AddSsdidSecretKeyStore(
        this IServiceCollection services,
        string secretPath)
    {
        // Remove any existing key store registration
        var existing = services.Where(d => d.ServiceType == typeof(IKeyStore)).ToList();
        foreach (var d in existing) services.Remove(d);

        services.AddSingleton<IKeyStore>(new SecretKeyStore(secretPath));
        return services;
    }

    /// <summary>
    /// Use an environment variable for server identity storage.
    /// Call BEFORE AddSsdidServer().
    ///
    /// Example:
    ///   builder.Services.AddSsdidEnvKeyStore("SSDID_IDENTITY_JSON");
    ///   builder.Services.AddSsdidServer(...);
    /// </summary>
    public static IServiceCollection AddSsdidEnvKeyStore(
        this IServiceCollection services,
        string envVarName = "SSDID_IDENTITY_JSON")
    {
        var existing = services.Where(d => d.ServiceType == typeof(IKeyStore)).ToList();
        foreach (var d in existing) services.Remove(d);

        services.AddSingleton<IKeyStore>(SecretKeyStore.FromEnvironment(envVarName));
        return services;
    }
}
