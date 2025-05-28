using EduVerse.Server.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Web;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Add distributed memory cache for session support
builder.Services.AddDistributedMemoryCache();

// Add Session support with proper cookie configuration
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None; // For development
});

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("http://localhost:3000")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Configure MongoDB Identity
ApplicationDbContext.ConfigureIdentity(builder.Services, builder.Configuration);

// Configure Identity options
builder.Services.Configure<IdentityOptions>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // User settings
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.User.RequireUniqueEmail = true;

    // Email confirmation
    options.SignIn.RequireConfirmedEmail = true;
});

// Configure Authentication
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.ASCII.GetBytes(jwtSettings["Key"] ?? throw new InvalidOperationException("JWT Key not configured"));

builder.Services.AddDataProtection()
    .SetApplicationName("EduVerse");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddCookie(IdentityConstants.ApplicationScheme, options =>
{
    options.LoginPath = "/api/auth/login";
    options.LogoutPath = "/api/auth/logout";
    options.Cookie.Name = "EduVerse.Auth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None; // For development
    options.ExpireTimeSpan = TimeSpan.FromDays(30);
    options.SlidingExpiration = true;
})
.AddCookie(IdentityConstants.ExternalScheme, options =>
{
    options.Cookie.Name = "EduVerse.External";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.None; // For development
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);
})
.AddGoogle(options =>
{
    var googleClientId = builder.Configuration["Authentication:Google:ClientId"]
        ?? throw new InvalidOperationException("Google ClientId not configured");
    var googleClientSecret = builder.Configuration["Authentication:Google:ClientSecret"]
        ?? throw new InvalidOperationException("Google ClientSecret not configured");

    options.ClientId = googleClientId;
    options.ClientSecret = googleClientSecret;
    options.CallbackPath = "/signin-google";

    // Set cookie options for Google authentication
    options.CorrelationCookie.SameSite = SameSiteMode.Lax;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.None; // Set to Always in production

    options.Events = new OAuthEvents
    {
        OnTicketReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Google authentication successful for user: {Email}",
                context.Principal?.FindFirstValue(ClaimTypes.Email));
            return Task.CompletedTask;
        },
        OnRemoteFailure = async context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("Google authentication failed: {Error}", context.Failure?.Message);
            await Task.Run(() =>
            {
                context.Response.Redirect($"http://localhost:3000/login?error={HttpUtility.UrlEncode(context.Failure?.Message)}");
                context.HandleResponse();
            });
        }
    };

    // Add required scopes
    options.Scope.Add("email");
    options.Scope.Add("profile");

    options.SaveTokens = true;
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Important: Order matters for middleware!
app.UseCors("AllowFrontend");

// Session must come before Authentication
app.UseSession();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Add direct handler for Google signin callback
app.MapGet("/signin-google", async (HttpContext context) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Direct signin-google callback hit");

    // Redirect to the controller action
    context.Response.Redirect("/api/GoogleAuth/callback");
});

// Add a simple health check endpoint
app.MapGet("/health", () => "OK");

// Log the startup
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("EduVerse server starting...");
logger.LogInformation($"Environment: {app.Environment.EnvironmentName}");
logger.LogInformation($"CORS Origins: {string.Join(", ", builder.Configuration.GetSection("CORS:AllowedOrigins").Get<string[]>() ?? new[] { "http://localhost:3000" })}");

app.Run();