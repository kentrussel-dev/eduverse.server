using EduVerse.Server.Data;
using EduVerse.Server.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using MailKit.Net.Smtp;
using MimeKit;
using System.Web;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.Logging;

namespace EduVerse.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            IWebHostEnvironment env,
            ILogger<AuthController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _env = env;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            try
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    FullName = model.FullName,
                    IsTeacher = model.IsTeacher
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (!result.Succeeded)
                {
                    _logger.LogWarning("Registration failed for {Email}: {Errors}", model.Email, string.Join(", ", result.Errors.Select(e => e.Description)));
                    return BadRequest(result.Errors);
                }

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action("ConfirmEmail", "Auth", new { userId = user.Id, token }, Request.Scheme);

                await SendEmailConfirmation(user.Email, confirmationLink);

                return Ok(new { Message = "Registration successful. Please check your email for confirmation." });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during registration for {Email}", model?.Email);
                return StatusCode(500, "An error occurred during registration. Please try again later.");
            }
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("Invalid credentials");
            }

            if (!await _userManager.IsEmailConfirmedAsync(user))
            {
                return StatusCode(401, "Please confirm your email address before logging in. Check your inbox for the confirmation link.");
            }

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
            if (!result.Succeeded)
            {
                return BadRequest("Invalid credentials");
            }

            // Return simple user data without cookies
            return Ok(new
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                IsTeacher = user.IsTeacher
            });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                await _signInManager.SignOutAsync();
                _logger.LogInformation("User logged out successfully");
                return Ok(new { Message = "Logout successful" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during logout");
                return StatusCode(500, "An error occurred during logout. Please try again later.");
            }
        }

        // Add this method to your AuthController class

        private IActionResult RedirectToFrontendWithTokenPopup(string token, ApplicationUser user)
        {
            // Create an HTML page that sends a message to the parent window
            var html = $@"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Google Authentication</title>
            </head>
            <body>
                <script>
                    window.opener.postMessage({{
                        type: 'GOOGLE_AUTH_SUCCESS',
                        token: '{token}',
                        user: {{
                            id: '{user.Id}',
                            email: '{user.Email}',
                            fullName: '{user.FullName}',
                            avatar: '{user.Avatar}',
                            isTeacher: {user.IsTeacher.ToString().ToLower()}
                        }}
                    }}, '{_configuration["Frontend:BaseUrl"]}');
                    window.close();
                </script>
                <p>Authentication successful! This window should close automatically.</p>
            </body>
            </html>";

            return Content(html, "text/html");
        }

        private IActionResult RedirectToFrontendWithSuccessPopup(ApplicationUser user)
        {
            var html = $@"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google Authentication Success</title>
    </head>
    <body>
        <script>
            try {{
                window.opener.postMessage({{
                    type: 'GOOGLE_AUTH_SUCCESS',
                    user: {{
                        id: '{user.Id}',
                        email: '{user.Email}',
                        fullName: '{user.FullName?.Replace("'", "\\'")}',
                        avatar: '{user.Avatar}',
                        isTeacher: {user.IsTeacher.ToString().ToLower()}
                    }}
                }}, '{_configuration["Frontend:BaseUrl"] ?? "http://localhost:3000"}');
                window.close();
            }} catch (error) {{
                console.error('Error sending message to parent:', error);
                document.body.innerHTML = '<p>Authentication successful! Please close this window and try again.</p>';
            }}
        </script>
        <p>Authentication successful! This window should close automatically.</p>
    </body>
    </html>";

            return Content(html, "text/html");
        }

        private IActionResult RedirectToFrontendWithErrorPopup(string error)
        {
            var html = $@"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google Authentication Error</title>
    </head>
    <body>
        <script>
            try {{
                window.opener.postMessage({{
                    type: 'GOOGLE_AUTH_ERROR',
                    error: '{HttpUtility.JavaScriptStringEncode(error)}'
                }}, '{_configuration["Frontend:BaseUrl"] ?? "http://localhost:3000"}');
                window.close();
            }} catch (err) {{
                console.error('Error sending message to parent:', err);
                document.body.innerHTML = '<p>Authentication failed: {HttpUtility.HtmlEncode(error)}</p><p>Please close this window and try again.</p>';
            }}
        </script>
        <p>Authentication failed: {HttpUtility.HtmlEncode(error)}</p>
        <p>This window should close automatically.</p>
    </body>
    </html>";

            return Content(html, "text/html");
        }


        [HttpGet("google-login")]
        public IActionResult GoogleLogin()
        {
            try
            {
                var properties = new AuthenticationProperties
                {
                    RedirectUri = Url.Action("GoogleResponse", "Auth"),
                    Items =
            {
                { "prompt", "select_account" },
                { "access_type", "offline" }
            }
                };

                _logger.LogInformation("Initiating Google login");
                return Challenge(properties, GoogleDefaults.AuthenticationScheme);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during Google login initiation");
                return RedirectToFrontendWithErrorPopup("Google login initiation failed");
            }
        }

        [HttpGet("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            try
            {
                var info = await _signInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    _logger.LogWarning("Google response: Failed to retrieve external login info");
                    return RedirectToFrontendWithErrorPopup("Failed to retrieve Google login information");
                }

                var email = info.Principal.FindFirstValue(ClaimTypes.Email);
                var name = info.Principal.FindFirstValue(ClaimTypes.Name);

                if (string.IsNullOrEmpty(email))
                {
                    _logger.LogWarning("Google response: No email provided");
                    return RedirectToFrontendWithErrorPopup("Email not provided by Google");
                }

                var user = await _userManager.FindByEmailAsync(email);

                if (user == null)
                {
                    // Create new user
                    user = new ApplicationUser
                    {
                        UserName = email,
                        Email = email,
                        FullName = name ?? email,
                        Avatar = "default.png",
                        EmailConfirmed = true, // Google emails are pre-confirmed
                        IsTeacher = false // Default to student, can be changed later
                    };

                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        _logger.LogError("Google response: Failed to create user {Email}: {Errors}",
                            email, string.Join(", ", createResult.Errors.Select(e => e.Description)));
                        return RedirectToFrontendWithErrorPopup("Failed to create user account");
                    }

                    _logger.LogInformation("Google response: Created new user {Email}", email);
                }

                // Check if user has this external login
                var existingLogins = await _userManager.GetLoginsAsync(user);
                if (!existingLogins.Any(x => x.LoginProvider == info.LoginProvider && x.ProviderKey == info.ProviderKey))
                {
                    var addLoginResult = await _userManager.AddLoginAsync(user, info);
                    if (!addLoginResult.Succeeded)
                    {
                        _logger.LogError("Google response: Failed to add login for {Email}: {Errors}",
                            email, string.Join(", ", addLoginResult.Errors.Select(e => e.Description)));
                        return RedirectToFrontendWithErrorPopup("Failed to link Google account");
                    }
                }

                // Sign the user in
                await _signInManager.SignInAsync(user, isPersistent: false);

                _logger.LogInformation("Google response: User {Email} signed in successfully", email);

                // Return success popup
                return RedirectToFrontendWithSuccessPopup(user);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during Google response handling");
                return RedirectToFrontendWithErrorPopup("An error occurred during Google authentication");
            }
        }



        private IActionResult RedirectToFrontendWithToken(string token, ApplicationUser user)
        {
            var frontendUrl = _configuration["Frontend:BaseUrl"] + _configuration["Frontend:CallbackPath"];
            var redirectUrl = $"{frontendUrl}?token={token}" +
                $"&userId={user.Id}" +
                $"&email={user.Email}" +
                $"&fullName={user.FullName}" +
                $"&avatar={user.Avatar}" +
                $"&isTeacher={user.IsTeacher}";

            return Redirect(redirectUrl);
        }

        private IActionResult RedirectToFrontendWithError(string error)
        {
            var frontendUrl = _configuration["Frontend:BaseUrl"] + _configuration["Frontend:CallbackPath"];
            return Redirect($"{frontendUrl}?error={Uri.EscapeDataString(error)}");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                return BadRequest("Invalid parameters");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                return BadRequest("Email confirmation failed");
            }

            return Ok("Email confirmed successfully");
        }



        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Unauthorized();
            }

            return Ok(new
            {
                user.Id,
                user.Email,
                user.FullName,
                user.Avatar,
                user.IsTeacher
            });
        }

        private string GenerateJwtToken(ApplicationUser user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim("avatar", user.Avatar),
                new Claim("isTeacher", user.IsTeacher.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiry = DateTime.Now.AddMinutes(Convert.ToInt32(_configuration["Jwt:ExpiryInMinutes"]));

            var token = new JwtSecurityToken(
                _configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: expiry,
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private async Task SendEmailConfirmation(string email, string confirmationLink)
        {
            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(_configuration["MailSettings:DisplayName"], _configuration["MailSettings:Mail"]));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = "Confirm your EduVerse account";

            var bodyBuilder = new BodyBuilder
            {
                HtmlBody = $@"
                    <h1>Welcome to EduVerse!</h1>
                    <p>Please confirm your email by clicking the link below:</p>
                    <a href='{confirmationLink}'>Confirm Email</a>
                    <p>If you didn't request this, please ignore this email.</p>
                "
            };

            message.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            await client.ConnectAsync(_configuration["MailSettings:Host"], Convert.ToInt32(_configuration["MailSettings:Port"]), false);
            // Use Username and Password for Mailtrap
            await client.AuthenticateAsync(_configuration["MailSettings:Username"], _configuration["MailSettings:Password"]);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
        [Authorize]
        [HttpPost("update-profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] UpdateProfileModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Unauthorized();
            }

            user.FullName = model.FullName;
            user.Avatar = model.Avatar;

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok(new
            {
                user.Id,
                user.Email,
                user.FullName,
                user.Avatar,
                user.IsTeacher
            });
        }

        public class UpdateProfileModel
        {
            public string FullName { get; set; }
            public string Avatar { get; set; }
        }

        [HttpGet("auth-mode")]
        public IActionResult GetAuthMode()
        {
            // For now, always return Cookie. You can make this dynamic if needed.
            return Ok(new { mode = "cookie" });
        }
    }

}