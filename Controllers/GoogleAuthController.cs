using System.Security.Claims;
using System.Web;
using EduVerse.Server.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace EduVerse.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GoogleAuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<GoogleAuthController> _logger;

        public GoogleAuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<GoogleAuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpGet("login")]
        public IActionResult Login(string? returnUrl)
        {
            // Configure the redirect URL for after authentication
            var redirectUrl = Url.Action(nameof(Callback), "GoogleAuth", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(
                GoogleDefaults.AuthenticationScheme, redirectUrl);

            _logger.LogInformation("Starting Google authentication with redirect URL: {RedirectUrl}", redirectUrl);
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("callback")]
        public async Task<IActionResult> Callback(string? returnUrl)
        {
            try
            {
                _logger.LogInformation("Google callback started");

                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    _logger.LogWarning("External login info was null");
                    return Redirect($"http://localhost:3000/login?error={HttpUtility.UrlEncode("Failed to retrieve Google login information")}");
                }

                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);

                if (string.IsNullOrEmpty(email))
                {
                    _logger.LogWarning("No email found in Google claims");
                    return Redirect($"http://localhost:3000/login?error={HttpUtility.UrlEncode("Email not provided by Google")}");
                }

                // Try to sign in with the external login
                var signInResult = await _signInManager.ExternalLoginSignInAsync(
                    info.LoginProvider, info.ProviderKey, isPersistent: true, bypassTwoFactor: true);

                if (signInResult.Succeeded)
                {
                    _logger.LogInformation("User {Email} signed in with Google", email);
                    return Redirect("http://localhost:3000/dashboard");
                }

                // If we get here, the user either doesn't exist or hasn't linked their Google account
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    // Create new user
                    user = new ApplicationUser
                    {
                        UserName = email,
                        Email = email,
                        FullName = name ?? email.Split('@')[0],
                        EmailConfirmed = true // Email is verified by Google
                    };

                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        _logger.LogError("Failed to create user for {Email}: {Errors}",
                            email, string.Join(", ", createResult.Errors.Select(e => e.Description)));
                        return Redirect($"http://localhost:3000/login?error={HttpUtility.UrlEncode("Failed to create account")}");
                    }
                }

                // Add the Google login to the user account
                var addLoginResult = await _userManager.AddLoginAsync(user, info);
                if (!addLoginResult.Succeeded)
                {
                    _logger.LogError("Failed to add Google login for {Email}: {Errors}",
                        email, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                    if (user.Id == default)
                    {
                        await _userManager.DeleteAsync(user);
                    }
                    return Redirect($"http://localhost:3000/login?error={HttpUtility.UrlEncode("Failed to link Google account")}");
                }

                // Sign in the user
                await _signInManager.SignInAsync(user, isPersistent: true);
                _logger.LogInformation("User {Email} successfully authenticated with Google", email);

                return Redirect("http://localhost:3000/dashboard");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during Google authentication");
                return Redirect($"http://localhost:3000/login?error={HttpUtility.UrlEncode("An error occurred during authentication")}");
            }
        }
    }
}