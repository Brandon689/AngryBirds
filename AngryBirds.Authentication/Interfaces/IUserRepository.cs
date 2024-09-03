using AngryBirds.AuthenticationLib.Models;
using AuthenticationLib;

namespace AngryBirds.AuthenticationLib.Interfaces;
public interface IUserRepository
{
    Task<User> GetByIdAsync(string id);
    Task<User> GetByUsernameAsync(string username);
    Task SaveUserAsync(User user);
    Task SaveRefreshTokenAsync(string userId, RefreshToken refreshToken);
    Task<(string NewAccessToken, string NewRefreshToken)> RotateRefreshTokenAsync(string userId, string oldRefreshToken);
    Task<IEnumerable<string>> GetUserPermissionsAsync(string userId);
}