using AngryBirds.Authorization.Handlers;
using AngryBirds.Authorization.Policies;
using AngryBirds.Authorization.Requirements;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace AngryBirds.Authorization.Extensions;

public static class AuthorizationServiceExtensions
{
    public static IServiceCollection AddAngryBirdsAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationCore(options =>
        {
            options.AddPolicy(PolicyNames.CanManageUsers, policy =>
                policy.Requirements.Add(new PermissionRequirement("ManageUsers")));
            options.AddPolicy(PolicyNames.CanViewReports, policy =>
                policy.Requirements.Add(new PermissionRequirement("ViewReports")));
        });

        services.AddSingleton<IAuthorizationHandler, PermissionHandler>();

        return services;
    }
}