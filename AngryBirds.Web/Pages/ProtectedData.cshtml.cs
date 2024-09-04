using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http.Headers;

namespace AngryBirds.Web.Pages
{
    public class ProtectedDataModel : PageModel
    {
        private readonly IHttpClientFactory _clientFactory;

        public ProtectedDataModel(IHttpClientFactory clientFactory)
        {
            _clientFactory = clientFactory;
        }

        [TempData]
        public string ProtectedMessage { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public void OnGet()
        {
            // This method is intentionally left empty
        }

        public async Task<IActionResult> OnPostFetchDataAsync()
        {
            var client = _clientFactory.CreateClient("AngryBirdsAPI");

            // Retrieve the token from the cookie
            var token = Request.Cookies["AccessToken"];

            if (string.IsNullOrEmpty(token))
            {
                ErrorMessage = "No authentication token found. Please log in.";
                return RedirectToPage();
            }

            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            try
            {
                var response = await client.GetAsync("/protected");

                if (response.IsSuccessStatusCode)
                {
                    ProtectedMessage = await response.Content.ReadAsStringAsync();
                }
                else
                {
                    ErrorMessage = $"Failed to fetch protected data. Status code: {response.StatusCode}";
                }
            }
            catch (HttpRequestException e)
            {
                ErrorMessage = $"An error occurred: {e.Message}";
            }

            return RedirectToPage();
        }
    }
}