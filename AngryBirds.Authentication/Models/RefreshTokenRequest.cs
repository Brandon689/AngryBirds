using System.ComponentModel.DataAnnotations;

namespace AngryBirds.AuthenticationLib.Models;

public class RefreshTokenRequest
{
    [Required(ErrorMessage = "Access token is required")]
    public string AccessToken { get; set; }

    [Required(ErrorMessage = "Refresh token is required")]
    public string RefreshToken { get; set; }
}