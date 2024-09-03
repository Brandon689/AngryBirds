using AngryBirds.AuthenticationLib.Configuration;
using AngryBirds.AuthenticationLib.Models;
using AngryBirds.AuthenticationLib.Services;
using AngryBirds.PasswordLib;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;

namespace AngryBirds.AuthenticationLib.Tests;

public class Tests
{
    [Fact]
    public async Task JwtService_GenerateAccessToken_ReturnsValidToken()
    {
        // Arrange
        var options = Options.Create(new JwtOptions
        {
            Key = "your-256-bit-secret-key-here-32-chars",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenExpiration = TimeSpan.FromMinutes(15)
        });
        var inMemoryCache = new InMemoryDistributedCache();
        var tokenRevocationService = new TokenRevocationService(inMemoryCache);
        var jwtService = new JwtService(options, tokenRevocationService);

        // Act
        var token = await jwtService.GenerateAccessTokenAsync("testUserId", new[] { "read" });

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);
    }

    [Fact]
    public async Task JwtService_GenerateRefreshToken_ReturnsValidToken()
    {
        // Arrange
        var options = Options.Create(new JwtOptions
        {
            Key = "your-256-bit-secret-key-here-32-chars",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenExpiration = TimeSpan.FromMinutes(15)
        });
        var inMemoryCache = new InMemoryDistributedCache();
        var tokenRevocationService = new TokenRevocationService(inMemoryCache);
        var jwtService = new JwtService(options, tokenRevocationService);

        // Act
        var refreshToken = await jwtService.GenerateRefreshTokenAsync();

        // Assert
        Assert.NotNull(refreshToken);
        Assert.NotEmpty(refreshToken);
    }

    [Fact]
    public void PasswordHasher_HashPassword_ReturnsHashedPassword()
    {
        // Arrange
        var password = "testPassword123";

        // Act
        var hashedPassword = PasswordHasher.HashPassword(password);

        // Assert
        Assert.NotNull(hashedPassword);
        Assert.NotEqual(password, hashedPassword);
    }

    [Fact]
    public void PasswordHasher_VerifyPassword_ReturnsTrue_ForCorrectPassword()
    {
        // Arrange
        var password = "testPassword123";
        var hashedPassword = PasswordHasher.HashPassword(password);

        // Act
        var result = PasswordHasher.VerifyPassword(password, hashedPassword);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void PasswordHasher_VerifyPassword_ReturnsFalse_ForIncorrectPassword()
    {
        // Arrange
        var password = "testPassword123";
        var wrongPassword = "wrongPassword123";
        var hashedPassword = PasswordHasher.HashPassword(password);

        // Act
        var result = PasswordHasher.VerifyPassword(wrongPassword, hashedPassword);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void User_SetPassword_HashesPassword()
    {
        // Arrange
        var user = new User();
        var password = "testPassword123";

        // Act
        user.SetPassword(password);

        // Assert
        Assert.NotNull(user.PasswordHash);
        Assert.NotEqual(password, user.PasswordHash);
    }

    [Fact]
    public void User_VerifyPassword_ReturnsTrue_ForCorrectPassword()
    {
        // Arrange
        var user = new User();
        var password = "testPassword123";
        user.SetPassword(password);

        // Act
        var result = user.VerifyPassword(password);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void User_VerifyPassword_ReturnsFalse_ForIncorrectPassword()
    {
        // Arrange
        var user = new User();
        var password = "testPassword123";
        var wrongPassword = "wrongPassword123";
        user.SetPassword(password);

        // Act
        var result = user.VerifyPassword(wrongPassword);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task JwtService_GenerateAccessToken_IncludesPermissions()
    {
        // Arrange
        var options = Options.Create(new JwtOptions
        {
            Key = "your-256-bit-secret-key-here-32-chars",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenExpiration = TimeSpan.FromMinutes(15)
        });
        var inMemoryCache = new InMemoryDistributedCache();
        var tokenRevocationService = new TokenRevocationService(inMemoryCache);
        var jwtService = new JwtService(options, tokenRevocationService);
        var permissions = new[] { "read", "write" };

        // Act
        var token = await jwtService.GenerateAccessTokenAsync("testUserId", permissions);

        // Assert
        Assert.NotNull(token);
        Assert.NotEmpty(token);

        var handler = new JwtSecurityTokenHandler();
        var jsonToken = handler.ReadToken(token) as JwtSecurityToken;

        Assert.NotNull(jsonToken);
        Assert.Contains(jsonToken.Claims, c => c.Type == "Permission" && c.Value == "read");
        Assert.Contains(jsonToken.Claims, c => c.Type == "Permission" && c.Value == "write");
    }

    [Fact]
    public void User_AddPermission_AddsPermission()
    {
        // Arrange
        var user = new User { Id = "testId", Username = "testUser" };

        // Act
        user.AddPermission("write");

        // Assert
        Assert.Contains("write", user.Permissions);
    }

    [Fact]
    public void User_RemovePermission_RemovesPermission()
    {
        // Arrange
        var user = new User { Id = "testId", Username = "testUser", Permissions = new List<string> { "read", "write" } };

        // Act
        user.RemovePermission("write");

        // Assert
        Assert.DoesNotContain("write", user.Permissions);
        Assert.Contains("read", user.Permissions);
    }

    [Fact]
    public void User_GetPermissions_ReturnsPermissions()
    {
        // Arrange
        var user = new User { Id = "testId", Username = "testUser", Permissions = new List<string> { "read", "write" } };

        // Act
        var permissions = user.Permissions;

        // Assert
        Assert.Equal(2, permissions.Count);
        Assert.Contains("read", permissions);
        Assert.Contains("write", permissions);
    }
}
