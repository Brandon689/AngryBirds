namespace AngryBirds.AuthenticationLib.Configuration;

public class JwtOptions
{
    public string Key { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public TimeSpan AccessTokenExpiration { get; set; } = TimeSpan.FromMinutes(15);
    public TimeSpan RefreshTokenExpiration { get; set; } = TimeSpan.FromDays(7);
}