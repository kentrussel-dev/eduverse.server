using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using EduVerse.Server.Data;
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson.Serialization.Attributes;

namespace EduVerse.Server.Realtime
{
    /// <summary>A player's saved world data: look, coins, furniture inventory and owned clothing.</summary>
    [BsonIgnoreExtraElements]
    public class WorldProfile
    {
        public AvatarLook Look { get; set; } = new();
        public int Coins { get; set; } = Catalog.StarterCoins;

        /// <summary>Furni type → how many the player has in their inventory (not placed in a room).</summary>
        public Dictionary<string, int> Furni { get; set; } = new(Catalog.StarterFurni);

        /// <summary>Ids of clothing catalog items the player bought.</summary>
        public List<string> Clothing { get; set; } = new();
        public DateTime? LastDailyBonus { get; set; }

        /// <summary>Which starter gifts this profile has had; older profiles are topped up once.</summary>
        public int? Version { get; set; }
    }

    public record ProfileDto(
        Guid UserId,
        string Name,
        bool IsTeacher,
        AvatarLook Look,
        int Coins,
        Dictionary<string, int> Furni,
        List<string> Clothing,
        bool DailyBonusAvailable);

    /// <summary>Loads and saves <see cref="WorldProfile"/>s.</summary>
    public interface IProfileStore
    {
        Task<WorldProfile?> LoadAsync(Guid userId);
        Task SaveAsync(Guid userId, WorldProfile profile);
    }

    /// <summary>Keeps the profile on the user document in MongoDB.</summary>
    public class IdentityProfileStore : IProfileStore
    {
        private readonly IServiceScopeFactory _scopes;

        public IdentityProfileStore(IServiceScopeFactory scopes)
        {
            _scopes = scopes;
        }

        public async Task<WorldProfile?> LoadAsync(Guid userId)
        {
            using var scope = _scopes.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByIdAsync(userId.ToString());
            return user?.WorldProfile;
        }

        public async Task SaveAsync(Guid userId, WorldProfile profile)
        {
            using var scope = _scopes.CreateScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByIdAsync(userId.ToString());
            if (user != null)
            {
                user.WorldProfile = profile;
                await users.UpdateAsync(user);
            }
        }
    }

    public class InMemoryProfileStore : IProfileStore
    {
        private readonly ConcurrentDictionary<Guid, WorldProfile> _profiles = new();

        public Task<WorldProfile?> LoadAsync(Guid userId) =>
            Task.FromResult(_profiles.TryGetValue(userId, out var profile) ? profile : null);

        public Task SaveAsync(Guid userId, WorldProfile profile)
        {
            _profiles[userId] = profile;
            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Shop, wallet and inventory rules. Each player's profile is cached and changed under a
    /// per-player lock so two quick purchases can't spend the same coins twice.
    /// </summary>
    public class ProfileService
    {
        private readonly IProfileStore _store;
        private readonly ConcurrentDictionary<Guid, SemaphoreSlim> _locks = new();
        private readonly ConcurrentDictionary<Guid, WorldProfile> _cache = new();

        public ProfileService(IProfileStore store)
        {
            _store = store;
        }

        public Func<DateTime> Clock { get; set; } = () => DateTime.UtcNow;

        /// <summary>The version of the starter gifts (1000 coins and 100 items).</summary>
        public const int CurrentVersion = 2;

        /// <summary>Loads a profile; a new player gets a random look for their gender.</summary>
        public async Task<WorldProfile> GetAsync(Guid userId, string? gender = null)
        {
            if (_cache.TryGetValue(userId, out var cached))
            {
                return cached;
            }
            var profile = await _store.LoadAsync(userId);
            if (profile == null)
            {
                profile = new WorldProfile { Look = AvatarLooks.Random(gender, Random.Shared), Version = CurrentVersion };
            }
            profile.Look ??= new AvatarLook();
            profile.Look.Gender = profile.Look.Gender is "girl" ? "girl" : "boy";
            profile.Furni ??= new Dictionary<string, int>();
            profile.Clothing ??= new List<string>();
            if ((profile.Version ?? 0) < CurrentVersion)
            {
                // Players from before the big furniture update get the new starter gifts too.
                profile.Coins = Math.Max(profile.Coins, Catalog.StarterCoins);
                foreach (var (type, count) in Catalog.StarterFurni)
                {
                    profile.Furni[type] = Math.Max(profile.Furni.GetValueOrDefault(type), count);
                }
                profile.Version = CurrentVersion;
                await _store.SaveAsync(userId, profile);
            }
            return _cache.GetOrAdd(userId, profile);
        }

        public ProfileDto ToDto(PlayerInfo player, WorldProfile profile) => new(
            player.UserId, player.Name, player.IsTeacher, profile.Look, profile.Coins,
            new Dictionary<string, int>(profile.Furni.Where(kv => kv.Value > 0)),
            profile.Clothing.ToList(),
            DailyBonusAvailable(profile));

        private bool DailyBonusAvailable(WorldProfile profile) =>
            profile.LastDailyBonus == null || profile.LastDailyBonus.Value.Date < Clock().Date;

        /// <summary>Changes a profile under the player's lock and saves it.</summary>
        private async Task<T> ChangeAsync<T>(Guid userId, Func<WorldProfile, T> change)
        {
            var gate = _locks.GetOrAdd(userId, _ => new SemaphoreSlim(1, 1));
            await gate.WaitAsync();
            try
            {
                var profile = await GetAsync(userId);
                var result = change(profile);
                await _store.SaveAsync(userId, profile);
                return result;
            }
            finally
            {
                gate.Release();
            }
        }

        /// <summary>Buys an item; admins (free = true) have unlimited coins.</summary>
        public Task<WorldProfile> BuyAsync(Guid userId, string itemId, bool free = false) => ChangeAsync(userId, profile =>
        {
            var item = Catalog.Find(itemId) ?? throw new WorldException("That item isn't in the shop.");
            if (item.Kind == CatalogKind.Clothing && profile.Clothing.Contains(item.Id))
            {
                throw new WorldException("You already own that.");
            }
            if (!free && profile.Coins < item.Price)
            {
                throw new WorldException($"You need {item.Price - profile.Coins} more coins.");
            }
            if (!free)
            {
                profile.Coins -= item.Price;
            }
            if (item.Kind == CatalogKind.Furni)
            {
                profile.Furni[item.Id] = profile.Furni.GetValueOrDefault(item.Id) + 1;
            }
            else
            {
                profile.Clothing.Add(item.Id);
            }
            return profile;
        });

        public Task<WorldProfile> ClaimDailyBonusAsync(Guid userId) => ChangeAsync(userId, profile =>
        {
            if (!DailyBonusAvailable(profile))
            {
                throw new WorldException("You already got today's coins. Come back tomorrow!");
            }
            profile.Coins += Catalog.DailyBonus;
            profile.LastDailyBonus = Clock();
            return profile;
        });

        public Task<WorldProfile> SetLookAsync(Guid userId, AvatarLook look) => ChangeAsync(userId, profile =>
        {
            AvatarLooks.Validate(look, profile);
            profile.Look = look;
            return profile;
        });

        /// <summary>Removes one furni from the inventory (to place it in a room).</summary>
        public Task<WorldProfile> TakeFurniAsync(Guid userId, string type) => ChangeAsync(userId, profile =>
        {
            if (profile.Furni.GetValueOrDefault(type) <= 0)
            {
                throw new WorldException("You don't have that in your inventory. Buy one in the shop!");
            }
            profile.Furni[type]--;
            return profile;
        });

        /// <summary>Puts furni back in the inventory (picked up, failed to place, or room deleted).</summary>
        public Task<WorldProfile> GiveFurniAsync(Guid userId, IEnumerable<string> types) => ChangeAsync(userId, profile =>
        {
            foreach (var type in types.Where(Catalog.IsFurniType))
            {
                profile.Furni[type] = profile.Furni.GetValueOrDefault(type) + 1;
            }
            return profile;
        });
    }

    public static class AvatarLooks
    {
        private static readonly Regex HexColor = new("^#[0-9a-fA-F]{6}$", RegexOptions.Compiled);

        private static readonly string[] Skins = { "#ffdbac", "#f1c27d", "#e0ac69", "#c68642", "#8d5524" };
        private static readonly string[] Hairs = { "#2b1b12", "#4a3021", "#7a4a2a", "#c65a1e", "#f2d16b", "#111111" };
        private static readonly string[] Shirts = { "#3f7fd9", "#e05780", "#2a9d8f", "#f4a261", "#9b5de5", "#e63946", "#ffffff", "#ffd166" };
        private static readonly string[] Pants = { "#2d3a4a", "#1d3557", "#6c757d", "#8d6e63", "#264653" };
        private static readonly string[] Shoes = { "#333333", "#ffffff", "#e63946", "#6d4c41" };

        /// <summary>Hair styles and bottoms offered first for each gender (any look can wear any style).</summary>
        public static readonly IReadOnlyDictionary<string, string[]> HairFor = new Dictionary<string, string[]>
        {
            ["boy"] = new[] { "short", "spiky", "curly" },
            ["girl"] = new[] { "long", "bun", "pigtails", "curly" },
        };

        public static readonly IReadOnlyDictionary<string, string[]> BottomsFor = new Dictionary<string, string[]>
        {
            ["boy"] = new[] { "pants", "shorts" },
            ["girl"] = new[] { "skirt", "pants", "shorts" },
        };

        /// <summary>A random free look for a new player.</summary>
        public static AvatarLook Random(string? gender, Random rng)
        {
            var g = gender is "girl" ? "girl" : gender is "boy" ? "boy" : (rng.Next(2) == 0 ? "boy" : "girl");
            T Pick<T>(IReadOnlyList<T> list) => list[rng.Next(list.Count)];
            return new AvatarLook
            {
                Gender = g,
                Skin = Pick(Skins),
                Hair = Pick(Hairs),
                HairStyle = Pick(HairFor[g]),
                Top = Pick(new[] { "tshirt", "longsleeve", "uniform" }),
                Shirt = Pick(Shirts),
                Bottom = Pick(BottomsFor[g]),
                Pants = Pick(Pants),
                Shoes = Pick(Shoes),
                Hat = "none",
                HatColor = "#e63946",
            };
        }

        /// <summary>Throws unless every color is valid and every style is free or owned.</summary>
        public static void Validate(AvatarLook? look, WorldProfile profile)
        {
            if (look == null)
            {
                throw new WorldException("Invalid avatar.");
            }
            look.Gender = look.Gender is "girl" ? "girl" : "boy";
            var colors = new[] { look.Skin, look.Hair, look.Shirt, look.Pants, look.HatColor, look.Shoes };
            if (!colors.All(c => c != null && HexColor.IsMatch(c)))
            {
                throw new WorldException("Invalid avatar colors.");
            }
            foreach (var (slot, value) in new[] { ("hairStyle", look.HairStyle), ("top", look.Top), ("bottom", look.Bottom), ("hat", look.Hat) })
            {
                if (value == null || !Catalog.IsKnownStyle(slot, value))
                {
                    throw new WorldException("Unknown clothing style.");
                }
                var item = Catalog.ClothingFor(slot, value);
                if (item != null && !profile.Clothing.Contains(item.Id))
                {
                    throw new WorldException($"Buy the {item.Name} in the shop first.");
                }
            }
        }
    }
}
