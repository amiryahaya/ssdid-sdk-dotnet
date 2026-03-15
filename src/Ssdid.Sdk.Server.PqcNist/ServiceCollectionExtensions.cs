using Microsoft.Extensions.DependencyInjection;
using Ssdid.Sdk.Server.Crypto;
using Ssdid.Sdk.Server.PqcNist.Providers;

namespace Ssdid.Sdk.Server.PqcNist;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSsdidPqcNist(this IServiceCollection services)
    {
        services.AddSingleton<ICryptoProvider, MlDsaProvider>();
        services.AddSingleton<ICryptoProvider, SlhDsaProvider>();
        return services;
    }
}
