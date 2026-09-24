using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using EduVerse.Server.Data;
using Microsoft.AspNetCore.Identity;

namespace EduVerse.Server.Realtime
{
    /// <summary>Loads and saves each user's avatar look.</summary>
    public interface IUserProfiles
    {
        Task<AvatarLook> GetLookAsync(Guid userId);
        Task SaveLookAsync(Guid userId, AvatarLook look);
    }

    public class IdentityUserProfiles : IUserProfiles
    {
        private readonly IServiceScopeFactory _scopes;

        public IdentityUserProfiles(IServiceScopeFactory scopes)
        {
            _scopes = scopes;
        }

        public async Task<AvatarLook> GetLookAsync(Guid userId)
        {
            using var scope = _scopes.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByIdAsync(userId.ToString());
            return user?.Look ?? AvatarLook.Default;
        }

        public async Task SaveLookAsync(Guid userId, AvatarLook look)
        {
            using var scope = _scopes.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByIdAsync(userId.ToString());
            if (user != null)
            {
                user.Look = look;
                await users.UpdateAsync(user);
            }
        }
    }

    public class InMemoryUserProfiles : IUserProfiles
    {
        private readonly ConcurrentDictionary<Guid, AvatarLook> _looks = new();

        public Task<AvatarLook> GetLookAsync(Guid userId) =>
            Task.FromResult(_looks.TryGetValue(userId, out var look) ? look : AvatarLook.Default);

        public Task SaveLookAsync(Guid userId, AvatarLook look)
        {
            _looks[userId] = look;
            return Task.CompletedTask;
        }
    }

    public static class AvatarLooks
    {
        private static readonly Regex HexColor = new("^#[0-9a-fA-F]{6}$", RegexOptions.Compiled);

        public static bool IsValid(AvatarLook? look) =>
            look != null && new[] { look.Skin, look.Hair, look.Shirt, look.Pants }.All(c => c != null && HexColor.IsMatch(c));
    }
}
