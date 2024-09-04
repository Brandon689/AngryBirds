using AngryBirds.AuthenticationLib.Models;

namespace AngryBirds.AuthenticationLib.Interfaces
{
    public interface IUserService
    {
        Task<User> AuthenticateAsync(string username, string password);
        Task<User> CreateUserAsync(string username, string password, IEnumerable<string> initialPermissions);
        Task<TokenResponse> GenerateTokensAsync(User user, string ipAddress);
        Task<TokenResponse> RefreshTokenAsync(string accessToken, string refreshToken);
        Task RevokeRefreshTokenAsync(string userId, string refreshToken);
        Task AddPermissionToUserAsync(string userId, string permission);
        Task RemovePermissionFromUserAsync(string userId, string permission);
        Task<IEnumerable<string>> GetUserPermissionsAsync(string userId);
    }
}