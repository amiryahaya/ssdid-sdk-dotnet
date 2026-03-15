using Microsoft.Extensions.DependencyInjection;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.KazSign.Providers;

namespace Ssdid.Sdk.Server.KazSign;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSsdidKazSign(this IServiceCollection services)
    {
        services.AddSingleton<ICryptoProvider, KazSignProvider>();
        return services;
    }
}
