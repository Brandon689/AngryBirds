namespace AngryBirds.AuthenticationLib.Interfaces;

public interface ITokenRevocationService
{
    Task RevokeTokenAsync(string token);
    Task<bool> IsTokenRevokedAsync(string token);
}