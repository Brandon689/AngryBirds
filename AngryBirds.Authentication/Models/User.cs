using AuthenticationLib;

namespace AngryBirds.AuthenticationLib.Models;

public class User
{
    public string Id { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public List<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    public List<string> Permissions { get; set; } = new List<string>();

    public void SetPassword(string password)
    {
        PasswordHash = PasswordLib.PasswordHasher.HashPassword(password);
    }

    public bool VerifyPassword(string password)
    {
        return PasswordLib.PasswordHasher.VerifyPassword(password, PasswordHash);
    }

    public void AddPermission(string permission)
    {
        if (!Permissions.Contains(permission))
        {
            Permissions.Add(permission);
        }
    }

    public void RemovePermission(string permission)
    {
        Permissions.Remove(permission);
    }

    public bool HasPermission(string permission)
    {
        return Permissions.Contains(permission);
    }
}