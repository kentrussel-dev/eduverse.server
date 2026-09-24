using EduVerse.Server.Realtime;
using Xunit;

namespace EduVerse.Server.Tests
{
    public class TemplateTests
    {
        private static readonly string[] DrawnTypes = { "whiteboard", "teacher_desk" };

        public static IEnumerable<object[]> Rooms() =>
            RoomTemplates.Names.Select(n => new object[] { n })
                .Concat(RoomTemplates.BuiltInRooms().Select(r => new object[] { r.Id }));

        private static RoomDefinition Load(string name) =>
            RoomTemplates.BuiltInRooms().FirstOrDefault(r => r.Id == name) ?? RoomTemplates.Create(name);

        [Theory]
        [MemberData(nameof(Rooms))]
        public void FurnitureFitsAndEveryTileCanBeReached(string name)
        {
            var room = Load(name);
            var depth = room.Layout.Count;
            var width = room.Layout[0].Length;
            bool IsFloor(int x, int y) => x >= 0 && y >= 0 && x < width && y < depth && room.Layout[y][x] != 'x';

            foreach (var item in room.Furni)
            {
                Assert.True(Catalog.IsFurniType(item.Type) || DrawnTypes.Contains(item.Type), $"{name}: unknown furni {item.Type}");
                Assert.True(IsFloor(item.X, item.Y), $"{name}: {item.Type} at {item.X},{item.Y} is off the floor");
                Assert.False(item.X == room.DoorX && item.Y == room.DoorY && !RoomTemplates.IsRug(item.Type), $"{name}: {item.Type} blocks the door");
            }
            var solid = room.Furni.Where(f => !RoomTemplates.IsRug(f.Type) && f.Type != "whiteboard")
                .GroupBy(f => (f.X, f.Y)).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
            Assert.True(solid.Count == 0, $"{name}: stacked furni at {string.Join(" ", solid)}");

            var blocked = room.Furni.Where(f => RoomTemplates.IsBlocking(f.Type)).Select(f => (f.X, f.Y)).ToHashSet();
            var seen = new HashSet<(int, int)> { (room.DoorX, room.DoorY) };
            var queue = new Queue<(int X, int Y)>(seen);
            while (queue.Count > 0)
            {
                var (x, y) = queue.Dequeue();
                foreach (var (nx, ny) in new[] { (x + 1, y), (x - 1, y), (x, y + 1), (x, y - 1) })
                {
                    if (IsFloor(nx, ny) && !blocked.Contains((nx, ny)) && seen.Add((nx, ny)))
                    {
                        queue.Enqueue((nx, ny));
                    }
                }
            }
            var unreachable = Enumerable.Range(0, width).SelectMany(x => Enumerable.Range(0, depth).Select(y => (x, y)))
                .Where(t => IsFloor(t.x, t.y) && !blocked.Contains(t) && !seen.Contains(t)).ToList();
            Assert.True(unreachable.Count == 0, $"{name}: can't reach {string.Join(" ", unreachable.Take(10))}");
        }

        [Fact]
        public void TheCatalogHasOverAHundredFurniAndPlayersStartWithAHundred()
        {
            Assert.True(Catalog.Assets.Count >= 150);
            Assert.Equal(100, Catalog.StarterFurni.Count);
            Assert.All(Catalog.StarterFurni.Keys, k => Assert.True(Catalog.IsFurniType(k)));
            Assert.Equal(1000, Catalog.StarterCoins);
        }

        [Fact]
        public void RandomLooksMatchTheGender()
        {
            var rng = new Random(1);
            for (var i = 0; i < 50; i++)
            {
                var girl = AvatarLooks.Random("girl", rng);
                Assert.Equal("girl", girl.Gender);
                Assert.Contains(girl.HairStyle, AvatarLooks.HairFor["girl"]);
                var boy = AvatarLooks.Random("boy", rng);
                Assert.Contains(boy.HairStyle, AvatarLooks.HairFor["boy"]);
                Assert.Contains(boy.Bottom, AvatarLooks.BottomsFor["boy"]);
                AvatarLooks.Validate(boy, new WorldProfile());
            }
        }
    }
}
