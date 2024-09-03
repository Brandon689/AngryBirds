using AngryBirds.AuthenticationLib.Configuration;
using AngryBirds.AuthenticationLib.Interfaces;
using AuthenticationLib;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AngryBirds.AuthenticationLib.Services;

public class JwtService : IJwtService
{
    private readonly JwtOptions _options;
    private readonly ITokenRevocationService _revocationService;

    public JwtService(IOptions<JwtOptions> options, ITokenRevocationService revocationService)
    {
        _options = options.Value;
        _revocationService = revocationService;
    }

    public async Task<string> GenerateAccessTokenAsync(string userId, IEnumerable<string> permissions)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, userId),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

        // Add permissions as claims
        claims.AddRange(permissions.Select(p => new Claim("Permission", p)));

        var token = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            expires: DateTime.UtcNow.Add(_options.AccessTokenExpiration),
            signingCredentials: credentials
        );

        return await Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));
    }

    public async Task<string> GenerateRefreshTokenAsync()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return await Task.FromResult(Convert.ToBase64String(randomNumber));
    }

    public async Task<ClaimsPrincipal> GetPrincipalFromExpiredTokenAsync(string token)
    {
        if (await _revocationService.IsTokenRevokedAsync(token))
        {
            throw new SecurityTokenException("Token has been revoked");
        }
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.Key)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return await Task.FromResult(principal);
    }
}