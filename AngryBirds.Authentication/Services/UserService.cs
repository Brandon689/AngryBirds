using AngryBirds.AuthenticationLib.Exceptions;
using AngryBirds.AuthenticationLib.Interfaces;
using AngryBirds.AuthenticationLib.Models;
using AuthenticationLib;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace AngryBirds.AuthenticationLib.Services;

public class UserService : IUserService
{
    private readonly IUserRepository _userRepository;
    private readonly IJwtService _jwtService;
    private readonly ILogger<UserService> _logger;

    public UserService(IUserRepository userRepository, IJwtService jwtService, ILogger<UserService> logger)
    {
        _userRepository = userRepository;
        _jwtService = jwtService;
        _logger = logger;
    }

    public async Task<User> AuthenticateAsync(string username, string password)
    {
        var user = await _userRepository.GetByUsernameAsync(username);
        if (user == null || !user.VerifyPassword(password))
        {
            _logger.LogWarning("Failed authentication attempt for username: {Username}", username);
            throw new AuthenticationException("Invalid username or password");
        }
        return user;
    }

    public async Task<User> CreateUserAsync(string username, string password, IEnumerable<string> initialPermissions)
    {
        var existingUser = await _userRepository.GetByUsernameAsync(username);
        if (existingUser != null)
        {
            throw new AuthenticationException("Username already exists");
        }

        var newUser = new User
        {
            Id = Guid.NewGuid().ToString(),
            Username = username
        };
        newUser.SetPassword(password);

        foreach (var permission in initialPermissions)
        {
            newUser.AddPermission(permission);
        }

        await _userRepository.SaveUserAsync(newUser);
        return newUser;
    }

    public async Task<(string AccessToken, string RefreshToken)> GenerateTokensAsync(User user, string ipAddress)
    {
        var permissions = await _userRepository.GetUserPermissionsAsync(user.Id);
        var accessToken = await _jwtService.GenerateAccessTokenAsync(user.Id, permissions);
        var refreshToken = await _jwtService.GenerateRefreshTokenAsync();

        var refreshTokenEntity = new RefreshToken
        {
            Token = refreshToken,
            Expires = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };

        await _userRepository.SaveRefreshTokenAsync(user.Id, refreshTokenEntity);

        return (accessToken, refreshToken);
    }

    public async Task<(string AccessToken, string RefreshToken)> RefreshTokenAsync(string accessToken, string refreshToken)
    {
        var principal = await _jwtService.GetPrincipalFromExpiredTokenAsync(accessToken);
        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var user = await GetUserByIdOrThrowAsync(userId);

        var existingRefreshToken = user.RefreshTokens.SingleOrDefault(rt => rt.Token == refreshToken);
        if (existingRefreshToken == null || !existingRefreshToken.IsActive)
        {
            throw new AuthenticationException("Invalid refresh token");
        }

        return await _userRepository.RotateRefreshTokenAsync(userId, refreshToken);
    }

    public async Task RevokeRefreshTokenAsync(string userId, string refreshToken)
    {
        var user = await GetUserByIdOrThrowAsync(userId);
        var token = user.RefreshTokens.SingleOrDefault(t => t.Token == refreshToken);
        if (token != null && token.IsActive)
        {
            token.Revoked = DateTime.UtcNow;
            await _userRepository.SaveUserAsync(user);
        }
    }

    public async Task AddPermissionToUserAsync(string userId, string permission)
    {
        var user = await GetUserByIdOrThrowAsync(userId);
        user.AddPermission(permission);
        await _userRepository.SaveUserAsync(user);
    }

    public async Task RemovePermissionFromUserAsync(string userId, string permission)
    {
        var user = await GetUserByIdOrThrowAsync(userId);
        user.RemovePermission(permission);
        await _userRepository.SaveUserAsync(user);
    }

    public async Task<IEnumerable<string>> GetUserPermissionsAsync(string userId)
    {
        var user = await GetUserByIdOrThrowAsync(userId);
        return user.Permissions;
    }

    private async Task<User> GetUserByIdOrThrowAsync(string userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        if (user == null)
        {
            throw new AuthenticationException("User not found");
        }
        return user;
    }
}