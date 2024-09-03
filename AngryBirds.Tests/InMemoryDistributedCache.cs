using Microsoft.Extensions.Caching.Distributed;

namespace AngryBirds.AuthenticationLib.Tests;

public class InMemoryDistributedCache : IDistributedCache
{
    private readonly Dictionary<string, byte[]> _cache = new Dictionary<string, byte[]>();

    public byte[] Get(string key) => _cache.TryGetValue(key, out var value) ? value : null;

    public Task<byte[]> GetAsync(string key, CancellationToken token = default)
        => Task.FromResult(Get(key));

    public void Set(string key, byte[] value, DistributedCacheEntryOptions options)
        => _cache[key] = value;

    public Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        Set(key, value, options);
        return Task.CompletedTask;
    }

    public void Refresh(string key) { }

    public Task RefreshAsync(string key, CancellationToken token = default)
        => Task.CompletedTask;

    public void Remove(string key) => _cache.Remove(key);

    public Task RemoveAsync(string key, CancellationToken token = default)
    {
        Remove(key);
        return Task.CompletedTask;
    }

    public string GetString(string key)
        => Get(key) != null ? System.Text.Encoding.UTF8.GetString(Get(key)) : null;

    public Task<string> GetStringAsync(string key, CancellationToken token = default)
        => Task.FromResult(GetString(key));

    public void SetString(string key, string value, DistributedCacheEntryOptions options)
        => Set(key, System.Text.Encoding.UTF8.GetBytes(value), options);

    public Task SetStringAsync(string key, string value, DistributedCacheEntryOptions options, CancellationToken token = default)
    {
        SetString(key, value, options);
        return Task.CompletedTask;
    }
}