using AngryBirds.AuthenticationLib.Configuration;
using AngryBirds.AuthenticationLib.Interfaces;
using AngryBirds.AuthenticationLib.Services;
using Microsoft.Extensions.DependencyInjection;

namespace AuthenticationLib;
public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, Action<JwtOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddScoped<IJwtService, JwtService>();
        services.AddScoped<IUserService, UserService>();
        return services;
    }
}