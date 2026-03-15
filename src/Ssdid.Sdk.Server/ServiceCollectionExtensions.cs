using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Ssdid.Sdk.Server.Auth;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.Crypto.Providers;
using Ssdid.Sdk.Server.Identity;
using Ssdid.Sdk.Server.Registration;
using Ssdid.Sdk.Server.Registry;
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

        // Identity
        services.AddSingleton<SsdidIdentity>(sp =>
        {
            var cryptoFactory = sp.GetRequiredService<CryptoProviderFactory>();
            return SsdidIdentity.LoadOrCreate(options.IdentityPath, options.Algorithm, cryptoFactory);
        });

        // Registry
        services.AddHttpClient<RegistryClient>(client =>
        {
            client.BaseAddress = new Uri(options.RegistryUrl);
            client.Timeout = TimeSpan.FromSeconds(15);
        });

        // Session (in-memory default)
        services.AddSingleton<InMemorySessionStore>();
        services.AddSingleton<ISessionStore>(sp => sp.GetRequiredService<InMemorySessionStore>());
        services.AddSingleton<ISseNotificationBus>(sp => sp.GetRequiredService<InMemorySessionStore>());

        // Auth
        services.AddScoped<SsdidAuthService>();

        // DID registration on startup
        services.AddHostedService<ServerRegistrationService>();

        return services;
    }
}
