namespace AngryBirds.Web.Extensions;

public static class HttpContextExtensions
{
    public static bool IsUserLoggedIn(this HttpContext context)
    {
        return context.Request.Cookies.ContainsKey("AccessToken");
    }
}
