using System.Security.Claims;

namespace AuthenticationLib;

public interface IJwtService
{
    Task<string> GenerateAccessTokenAsync(string userId, IEnumerable<string> permissions);
    Task<string> GenerateRefreshTokenAsync();
    Task<ClaimsPrincipal> GetPrincipalFromExpiredTokenAsync(string token);
}