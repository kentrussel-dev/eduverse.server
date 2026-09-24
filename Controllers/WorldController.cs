using System.Security.Claims;
using EduVerse.Server.Realtime;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EduVerse.Server.Controllers
{
    /// <summary>World data for the website (the game itself talks over the SignalR hub).</summary>
    [ApiController]
    [Route("api/world")]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class WorldController : ControllerBase
    {
        private readonly ProfileService _profiles;

        public WorldController(ProfileService profiles)
        {
            _profiles = profiles;
        }

        /// <summary>Your avatar and coins, for the avatar preview on the dashboard.</summary>
        [HttpGet("profile")]
        public async Task<IActionResult> Profile()
        {
            if (!Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            {
                return Unauthorized();
            }
            var profile = await _profiles.GetAsync(userId, User.FindFirstValue("gender"));
            return Ok(new
            {
                profile.Look,
                profile.Coins,
                FurniCount = profile.Furni.Values.Sum(),
                Clothing = profile.Clothing.Count,
            });
        }
    }
}
