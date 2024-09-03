using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AngryBirds.Web.Pages
{
    public class LogoutModel : PageModel
    {
        public bool LogoutSuccessful { get; set; }

        public void OnGet()
        {
            LogoutSuccessful = false;
        }

        public IActionResult OnPost()
        {
            // Remove the AccessToken cookie
            Response.Cookies.Delete("AccessToken");

            // Remove the RefreshToken cookie if you're using it
            Response.Cookies.Delete("RefreshToken");

            // Set the flag to indicate successful logout
            LogoutSuccessful = true;

            // Return to the same page
            return Page();
        }
    }
}
