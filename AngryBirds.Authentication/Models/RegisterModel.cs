using System.ComponentModel.DataAnnotations;

namespace AngryBirds.AuthenticationLib.Models;

public class RegisterModel
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
    public string Username { get; set; }

    [Required(ErrorMessage = "Password is required")]
    [StringLength(100, MinimumLength = 10, ErrorMessage = "Password must be between 10 and 100 characters")]
    public string Password { get; set; }
}