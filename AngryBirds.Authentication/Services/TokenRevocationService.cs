using AngryBirds.AuthenticationLib.Interfaces;
using Microsoft.Extensions.Caching.Distributed;

namespace AngryBirds.AuthenticationLib.Services;

public class TokenRevocationService : ITokenRevocationService
{
    private readonly IDistributedCache _cache;

    public TokenRevocationService(IDistributedCache cache)
    {
        _cache = cache;
    }

    public async Task RevokeTokenAsync(string token)
    {
        await _cache.SetStringAsync(token, "revoked", new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(7)
        });
    }

    public async Task<bool> IsTokenRevokedAsync(string token)
    {
        return await _cache.GetStringAsync(token) != null;
    }
}