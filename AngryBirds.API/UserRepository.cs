using AngryBirds.AuthenticationLib.Interfaces;
using AngryBirds.AuthenticationLib.Models;
using AuthenticationLib;
using Microsoft.Data.Sqlite;
using System.Security.Authentication;
using System.Text.Json;

namespace AngryBirds.API;

public class UserRepository : IUserRepository
{
    private readonly string _connectionString;
    private readonly IJwtService _jwtService;

    public UserRepository(string connectionString, IJwtService jwtService)
    {
        _connectionString = connectionString;
        _jwtService = jwtService;
        InitializeDatabase();
    }

    private void InitializeDatabase()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();
        command.CommandText = @"
                CREATE TABLE IF NOT EXISTS Users (
                    Id TEXT PRIMARY KEY,
                    Username TEXT UNIQUE,
                    PasswordHash TEXT,
                    RefreshTokens TEXT,
                    Permissions TEXT
                )";
        command.ExecuteNonQuery();
    }

    public async Task<User> GetByIdAsync(string id)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM Users WHERE Id = @Id";
        command.Parameters.AddWithValue("@Id", id);

        using var reader = await command.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return CreateUserFromReader(reader);
        }

        return null;
    }

    public async Task<User> GetByUsernameAsync(string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var command = connection.CreateCommand();
        command.CommandText = "SELECT * FROM Users WHERE Username = @Username";
        command.Parameters.AddWithValue("@Username", username);

        using var reader = await command.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return CreateUserFromReader(reader);
        }

        return null;
    }

    public async Task SaveUserAsync(User user)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var command = connection.CreateCommand();
        command.CommandText = @"
                INSERT OR REPLACE INTO Users (Id, Username, PasswordHash, RefreshTokens, Permissions)
                VALUES (@Id, @Username, @PasswordHash, @RefreshTokens, @Permissions)";

        command.Parameters.AddWithValue("@Id", user.Id);
        command.Parameters.AddWithValue("@Username", user.Username);
        command.Parameters.AddWithValue("@PasswordHash", user.PasswordHash);
        command.Parameters.AddWithValue("@RefreshTokens", JsonSerializer.Serialize(user.RefreshTokens));
        command.Parameters.AddWithValue("@Permissions", JsonSerializer.Serialize(user.Permissions));

        await command.ExecuteNonQueryAsync();
    }

    public async Task SaveRefreshTokenAsync(string userId, RefreshToken refreshToken)
    {
        var user = await GetByIdAsync(userId);
        if (user != null)
        {
            user.RefreshTokens.Add(refreshToken);
            await SaveUserAsync(user);
        }
    }

    public async Task<(string NewAccessToken, string NewRefreshToken)> RotateRefreshTokenAsync(string userId, string oldRefreshToken)
    {
        var user = await GetByIdAsync(userId);
        if (user == null)
            throw new AuthenticationException("User not found");

        var oldToken = user.RefreshTokens.SingleOrDefault(rt => rt.Token == oldRefreshToken);
        if (oldToken == null || !oldToken.IsActive)
            throw new AuthenticationException("Invalid refresh token");

        // Generate new refresh token
        var newRefreshToken = new RefreshToken
        {
            Token = await _jwtService.GenerateRefreshTokenAsync(),
            Expires = DateTime.UtcNow.AddDays(7),
            Created = DateTime.UtcNow,
            CreatedByIp = oldToken.CreatedByIp
        };

        // Remove old refresh token and add new one
        user.RefreshTokens.Remove(oldToken);
        user.RefreshTokens.Add(newRefreshToken);

        // Generate new access token
        var newAccessToken = await _jwtService.GenerateAccessTokenAsync(user.Id, user.Permissions);

        // Save changes
        await SaveUserAsync(user);

        return (newAccessToken, newRefreshToken.Token);
    }

    public async Task<IEnumerable<string>> GetUserPermissionsAsync(string userId)
    {
        var user = await GetByIdAsync(userId);
        return user?.Permissions ?? Enumerable.Empty<string>();
    }

    private User CreateUserFromReader(SqliteDataReader reader)
    {
        return new User
        {
            Id = reader.GetString(0),
            Username = reader.GetString(1),
            PasswordHash = reader.GetString(2),
            RefreshTokens = JsonSerializer.Deserialize<List<RefreshToken>>(reader.GetString(3)) ?? new List<RefreshToken>(),
            Permissions = JsonSerializer.Deserialize<List<string>>(reader.GetString(4)) ?? new List<string>()
        };
    }
}