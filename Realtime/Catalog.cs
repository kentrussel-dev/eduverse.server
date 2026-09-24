using System.Reflection;
using System.Text.Json;

namespace EduVerse.Server.Realtime
{
    public enum CatalogKind
    {
        Furni = 0,
        Clothing = 1
    }

    /// <summary>Something sold in the shop. Furni items use the furni type as their id.</summary>
    public record CatalogItem(string Id, string Name, CatalogKind Kind, int Price, string Category,
        string? Slot = null, string? Value = null);

    /// <summary>Everything in the shop, plus the free clothing styles every avatar can use.</summary>
    public static class Catalog
    {
        public const int StarterCoins = 1000;
        public const int DailyBonus = 50;

        /// <summary>
        /// Furniture rendered from the CC0 Kenney and KayKit 3D kits (see FurniCatalog.json and
        /// public/furni in the frontend), with whether avatars sit on it or walk over it.
        /// </summary>
        public static readonly IReadOnlyList<FurniAsset> Assets = LoadAssets();

        public static readonly IReadOnlyList<CatalogItem> Items = BuiltInItems()
            .Concat(Assets.Select(a => new CatalogItem(a.Id, a.Name, CatalogKind.Furni, PriceFor(a.Category), a.Category)))
            .ToList();

        private static List<CatalogItem> BuiltInItems() => new()
        {
            // Furniture
            new("chair", "School Chair", CatalogKind.Furni, 10, "Seating"),
            new("stool", "Stool", CatalogKind.Furni, 8, "Seating"),
            new("sofa", "Comfy Sofa", CatalogKind.Furni, 25, "Seating"),
            new("beanbag", "Beanbag", CatalogKind.Furni, 20, "Seating"),
            new("desk", "Student Desk", CatalogKind.Furni, 15, "Study"),
            new("table", "Wooden Table", CatalogKind.Furni, 15, "Study"),
            new("bookshelf", "Bookshelf", CatalogKind.Furni, 30, "Study"),
            new("computer", "Computer Desk", CatalogKind.Furni, 50, "Study"),
            new("locker", "Locker", CatalogKind.Furni, 20, "Study"),
            new("plant", "Potted Plant", CatalogKind.Furni, 10, "Decor"),
            new("rug", "Red Rug", CatalogKind.Furni, 12, "Decor"),
            new("lamp", "Floor Lamp", CatalogKind.Furni, 15, "Decor"),
            new("teddy", "Teddy Bear", CatalogKind.Furni, 35, "Decor"),
            new("duck", "Rubber Duck", CatalogKind.Furni, 5, "Decor"),
            new("trophy", "Golden Trophy", CatalogKind.Furni, 100, "Decor"),
            new("aquarium", "Aquarium", CatalogKind.Furni, 60, "Fun"),
            new("tv", "Television", CatalogKind.Furni, 45, "Fun"),
            new("arcade", "Arcade Machine", CatalogKind.Furni, 80, "Fun"),
            new("block_red", "Red Block", CatalogKind.Furni, 5, "Blocks"),
            new("block_blue", "Blue Block", CatalogKind.Furni, 5, "Blocks"),
            new("block_yellow", "Yellow Block", CatalogKind.Furni, 5, "Blocks"),
            new("block_green", "Green Block", CatalogKind.Furni, 5, "Blocks"),

            // Clothing
            new("top_hoodie", "Cardigan", CatalogKind.Clothing, 40, "Tops", "top", "hoodie"),
            new("top_dress", "Dress (top + skirt)", CatalogKind.Clothing, 40, "Tops", "top", "dress"),
            new("top_jersey", "V-neck Tee", CatalogKind.Clothing, 60, "Tops", "top", "jersey"),
            new("hat_cap", "Baseball Cap", CatalogKind.Clothing, 30, "Hats", "hat", "cap"),
            new("hat_beanie", "Bandana", CatalogKind.Clothing, 30, "Hats", "hat", "beanie"),
            new("hat_bow", "Headband", CatalogKind.Clothing, 25, "Hats", "hat", "bow"),
            new("hat_party", "Holiday Hat", CatalogKind.Clothing, 50, "Hats", "hat", "party"),
            new("hat_headphones", "Sunglasses", CatalogKind.Clothing, 60, "Hats", "hat", "headphones"),
            new("hat_gradcap", "Top Hat", CatalogKind.Clothing, 100, "Hats", "hat", "gradcap"),
            new("hat_crown", "Crown", CatalogKind.Clothing, 200, "Hats", "hat", "crown"),
        };

        private static int PriceFor(string category) => category switch
        {
            "Rugs" or "Plants" => 10,
            "Seating" or "Lights" or "Decor" => 20,
            "Bedroom" or "Bathroom" or "Fun" => 40,
            _ => 25,
        };

        private static List<FurniAsset> LoadAssets()
        {
            using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("EduVerse.Server.Realtime.FurniCatalog.json")
                ?? throw new InvalidOperationException("FurniCatalog.json is missing from the build.");
            return JsonSerializer.Deserialize<List<FurniAsset>>(stream, new JsonSerializerOptions { PropertyNameCaseInsensitive = true })!;
        }

        /// <summary>Styles anyone can wear without buying them.</summary>
        public static readonly IReadOnlyDictionary<string, string[]> FreeStyles = new Dictionary<string, string[]>
        {
            ["hairStyle"] = new[] { "short", "long", "spiky", "bun", "curly", "pigtails", "bald" },
            ["top"] = new[] { "tshirt", "longsleeve", "uniform" },
            ["bottom"] = new[] { "pants", "shorts", "skirt" },
            ["hat"] = new[] { "none" },
        };

        /// <summary>
        /// Furniture every new player starts with so they can decorate right away: one each of
        /// 100 different items, picked from every category in turn.
        /// </summary>
        public static readonly IReadOnlyDictionary<string, int> StarterFurni = PickStarterFurni(100);

        private static Dictionary<string, int> PickStarterFurni(int count)
        {
            var queues = Assets.GroupBy(a => a.Category).Select(g => new Queue<FurniAsset>(g)).ToList();
            var picked = new Dictionary<string, int>();
            while (picked.Count < count && queues.Any(q => q.Count > 0))
            {
                foreach (var queue in queues.Where(q => q.Count > 0))
                {
                    if (picked.Count < count)
                    {
                        picked[queue.Dequeue().Id] = 1;
                    }
                }
            }
            return picked;
        }

        public static FurniAsset? Asset(string type) => Assets.FirstOrDefault(a => a.Id == type);

        public static CatalogItem? Find(string id) => Items.FirstOrDefault(i => i.Id == id);

        public static bool IsFurniType(string type) => Items.Any(i => i.Kind == CatalogKind.Furni && i.Id == type);

        /// <summary>The shop item that unlocks a style, or null if the style is free (or unknown).</summary>
        public static CatalogItem? ClothingFor(string slot, string value) =>
            Items.FirstOrDefault(i => i.Kind == CatalogKind.Clothing && i.Slot == slot && i.Value == value);

        public static bool IsKnownStyle(string slot, string value) =>
            (FreeStyles.TryGetValue(slot, out var free) && free.Contains(value)) || ClothingFor(slot, value) != null;
    }

    /// <summary>A piece of furniture from the 3D kits.</summary>
    public record FurniAsset(string Id, string Name, string Category, bool Seat, bool Walk);
}
