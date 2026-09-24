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
        public const int StarterCoins = 200;
        public const int DailyBonus = 50;

        public static readonly IReadOnlyList<CatalogItem> Items = new List<CatalogItem>
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
            new("top_hoodie", "Hoodie", CatalogKind.Clothing, 40, "Tops", "top", "hoodie"),
            new("top_dress", "Dress", CatalogKind.Clothing, 40, "Tops", "top", "dress"),
            new("top_jersey", "Sports Jersey", CatalogKind.Clothing, 60, "Tops", "top", "jersey"),
            new("hat_cap", "Baseball Cap", CatalogKind.Clothing, 30, "Hats", "hat", "cap"),
            new("hat_beanie", "Beanie", CatalogKind.Clothing, 30, "Hats", "hat", "beanie"),
            new("hat_bow", "Hair Bow", CatalogKind.Clothing, 25, "Hats", "hat", "bow"),
            new("hat_party", "Party Hat", CatalogKind.Clothing, 50, "Hats", "hat", "party"),
            new("hat_headphones", "Headphones", CatalogKind.Clothing, 60, "Hats", "hat", "headphones"),
            new("hat_gradcap", "Graduation Cap", CatalogKind.Clothing, 100, "Hats", "hat", "gradcap"),
            new("hat_crown", "Crown", CatalogKind.Clothing, 200, "Hats", "hat", "crown"),
        };

        /// <summary>Styles anyone can wear without buying them.</summary>
        public static readonly IReadOnlyDictionary<string, string[]> FreeStyles = new Dictionary<string, string[]>
        {
            ["hairStyle"] = new[] { "short", "long", "spiky", "bun", "curly", "pigtails", "bald" },
            ["top"] = new[] { "tshirt", "longsleeve", "uniform" },
            ["bottom"] = new[] { "pants", "shorts", "skirt" },
            ["hat"] = new[] { "none" },
        };

        /// <summary>Furniture every new player starts with so they can decorate right away.</summary>
        public static readonly IReadOnlyDictionary<string, int> StarterFurni = new Dictionary<string, int>
        {
            ["chair"] = 2,
            ["table"] = 1,
            ["plant"] = 2,
            ["rug"] = 2,
            ["sofa"] = 1,
            ["block_blue"] = 3,
        };

        public static CatalogItem? Find(string id) => Items.FirstOrDefault(i => i.Id == id);

        public static bool IsFurniType(string type) => Items.Any(i => i.Kind == CatalogKind.Furni && i.Id == type);

        /// <summary>The shop item that unlocks a style, or null if the style is free (or unknown).</summary>
        public static CatalogItem? ClothingFor(string slot, string value) =>
            Items.FirstOrDefault(i => i.Kind == CatalogKind.Clothing && i.Slot == slot && i.Value == value);

        public static bool IsKnownStyle(string slot, string value) =>
            (FreeStyles.TryGetValue(slot, out var free) && free.Contains(value)) || ClothingFor(slot, value) != null;
    }
}
