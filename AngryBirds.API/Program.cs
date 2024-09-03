using AngryBirds.AuthenticationLib.Exceptions;
using AngryBirds.AuthenticationLib.Interfaces;
using AngryBirds.AuthenticationLib.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });

builder.Services.AddAuthorization();

// Add your IUserRepository implementation here
//builder.Services.AddScoped<IUserRepository, UserRepository>();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseAuthentication();
app.UseAuthorization();

if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.MapPost("/register", async (HttpContext httpContext, RegisterModel model, IUserService userService) =>
{
    try
    {
        var defaultPermissions = new[] { "basic_access" };
        var user = await userService.CreateUserAsync(model.Username, model.Password, defaultPermissions);
        var ipAddress = GetIpAddress(httpContext);
        var (accessToken, refreshToken) = await userService.GenerateTokensAsync(user, ipAddress);
        return Results.Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
    }
    catch (AuthenticationException ex)
    {
        return Results.BadRequest(ex.Message);
    }
});

app.MapPost("/login", async (HttpContext httpContext, LoginModel model, IUserService userService) =>
{
    var user = await userService.AuthenticateAsync(model.Username, model.Password);
    if (user == null)
        return Results.Unauthorized();

    var ipAddress = GetIpAddress(httpContext);
    var (accessToken, refreshToken) = await userService.GenerateTokensAsync(user, ipAddress);
    return Results.Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
});

string GetIpAddress(HttpContext context)
{
    if (context.Request.Headers.ContainsKey("X-Forwarded-For"))
        return context.Request.Headers["X-Forwarded-For"];
    else
        return context.Connection.RemoteIpAddress.MapToIPv4().ToString();
}

app.MapPost("/refresh-token", async (RefreshTokenRequest request, IUserService userService) =>
{
    try
    {
        var (accessToken, refreshToken) = await userService.RefreshTokenAsync(request.AccessToken, request.RefreshToken);
        return Results.Ok(new { AccessToken = accessToken, RefreshToken = refreshToken });
    }
    catch (AuthenticationException ex)
    {
        return Results.Unauthorized();
    }
});

app.MapPost("/revoke-token", [Authorize] async (HttpContext context, IUserService userService) =>
{
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
    var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    await userService.RevokeRefreshTokenAsync(userId, token);
    return Results.Ok("Token revoked successfully");
});

app.MapGet("/protected", [Authorize] () => "This is a protected endpoint")
    .RequireAuthorization();

app.MapPost("/add-permission", [Authorize] async (string userId, string permission, IUserService userService) =>
{
    await userService.AddPermissionToUserAsync(userId, permission);
    return Results.Ok($"Permission '{permission}' added to user {userId}");
}).RequireAuthorization("ManagePermissions");

app.MapPost("/remove-permission", [Authorize] async (string userId, string permission, IUserService userService) =>
{
    await userService.RemovePermissionFromUserAsync(userId, permission);
    return Results.Ok($"Permission '{permission}' removed from user {userId}");
}).RequireAuthorization("ManagePermissions");

app.MapGet("/user-permissions", [Authorize] async (string userId, IUserService userService) =>
{
    var permissions = await userService.GetUserPermissionsAsync(userId);
    return Results.Ok(permissions);
}).RequireAuthorization("ViewPermissions");

app.Run();