using System.Text.Json.Serialization;

namespace AngryBirds.AuthenticationLib.Models
{
    public class TokenResponse
    {
        [JsonPropertyName("accessToken")]
        public string AccessToken { get; set; }

        [JsonPropertyName("refreshToken")]
        public string RefreshToken { get; set; }
    }
}