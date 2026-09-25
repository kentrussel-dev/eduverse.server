using EduVerse.Server.Realtime;

namespace EduVerse.Server.Tests
{
    public class ShopTests
    {
        private static readonly Guid User = Guid.NewGuid();

        [Fact]
        public async Task NewPlayersGetStarterCoinsAndFurni()
        {
            var profile = await new ProfileService(new InMemoryProfileStore()).GetAsync(User);
            Assert.Equal(Catalog.StarterCoins, profile.Coins);
            Assert.Equal(100, profile.Furni.Count(kv => kv.Value > 0));
        }

        [Fact]
        public async Task BuyingSpendsCoinsAndAddsItems()
        {
            var shop = new ProfileService(new InMemoryProfileStore());
            var profile = await shop.BuyAsync(User, "teddy");
            Assert.Equal(Catalog.StarterCoins - 35, profile.Coins);
            Assert.Equal(1, profile.Furni["teddy"]);

            profile = await shop.BuyAsync(User, "hat_cap");
            Assert.Contains("hat_cap", profile.Clothing);
            var ex = await Assert.ThrowsAsync<WorldException>(() => shop.BuyAsync(User, "hat_cap"));
            Assert.Contains("already own", ex.Message);
        }

        [Fact]
        public async Task CannotBuyWithoutEnoughCoins()
        {
            var shop = new ProfileService(new InMemoryProfileStore());
            for (var i = 0; i < Catalog.StarterCoins / 100; i++)
            {
                await shop.BuyAsync(User, "trophy"); // 100 each, until the starter coins are gone
            }
            var ex = await Assert.ThrowsAsync<WorldException>(() => shop.BuyAsync(User, "duck"));
            Assert.Contains("more coins", ex.Message);
        }

        [Fact]
        public async Task DailyBonusOncePerDay()
        {
            var now = new DateTime(2026, 3, 1, 8, 0, 0, DateTimeKind.Utc);
            var shop = new ProfileService(new InMemoryProfileStore()) { Clock = () => now };
            var profile = await shop.ClaimDailyBonusAsync(User);
            Assert.Equal(Catalog.StarterCoins + Catalog.DailyBonus, profile.Coins);
            await Assert.ThrowsAsync<WorldException>(() => shop.ClaimDailyBonusAsync(User));
            now = now.AddDays(1);
            await shop.ClaimDailyBonusAsync(User);
        }

        [Fact]
        public async Task PaidStylesMustBeOwned()
        {
            var shop = new ProfileService(new InMemoryProfileStore());
            var look = new AvatarLook { Hat = "crown", HairStyle = "pigtails", Bottom = "skirt" };
            var ex = await Assert.ThrowsAsync<WorldException>(() => shop.SetLookAsync(User, look));
            Assert.Contains("Crown", ex.Message);

            await shop.BuyAsync(User, "hat_crown");
            var profile = await shop.SetLookAsync(User, look);
            Assert.Equal("crown", profile.Look.Hat);

            await Assert.ThrowsAsync<WorldException>(() => shop.SetLookAsync(User, new AvatarLook { Top = "spacesuit" }));
            await Assert.ThrowsAsync<WorldException>(() => shop.SetLookAsync(User, new AvatarLook { Skin = "red" }));
        }

        [Fact]
        public async Task InventoryTakeAndGive()
        {
            var shop = new ProfileService(new InMemoryProfileStore());
            var type = Catalog.StarterFurni.Keys.First();
            await shop.TakeFurniAsync(User, type);
            await Assert.ThrowsAsync<WorldException>(() => shop.TakeFurniAsync(User, type));
            var profile = await shop.GiveFurniAsync(User, new[] { type, "not_a_furni" });
            Assert.Equal(1, profile.Furni[type]);
            Assert.False(profile.Furni.ContainsKey("not_a_furni"));
        }
    }

    public class RoomFeatureTests
    {
        private static readonly PlayerInfo Owner = new(Guid.NewGuid(), "Ana R.", false, AvatarLook.Default);
        private static readonly PlayerInfo Guest = new(Guid.NewGuid(), "Ben S.", false, AvatarLook.Default);
        private static readonly PlayerInfo Teacher = new(Guid.NewGuid(), "Ms. Cruz", true, AvatarLook.Default);

        private static async Task<(WorldState World, InMemoryRoomStore Store, string RoomId)> WorldWithRoom(RoomKind kind = RoomKind.Public)
        {
            var store = new InMemoryRoomStore();
            var world = new WorldState(store);
            await world.EnsureLoadedAsync();
            var room = await world.CreateRoomAsync(Owner, new CreateRoomRequest("Ana's Hangout", "", kind, "empty"));
            world.Join("owner", Owner, room.Id);
            world.Join("guest", Guest, room.Id);
            return (world, store, room.Id);
        }

        [Fact]
        public async Task OwnerPlacesRotatesAndPicksUpFurni()
        {
            var (world, store, roomId) = await WorldWithRoom();
            var (room, item) = await world.PlaceFurniAsync("owner", "block_red", 3, 3, "se");
            Assert.False(room.Walkable[3, 3]);
            Assert.Contains(store.LoadRoomsAsync().Result.Single(r => r.Id == roomId).Furni, f => f.Id == item.Id);

            var (_, rotated) = await world.RotateFurniAsync("owner", item.Id);
            Assert.Equal("sw", rotated.Dir);

            var (_, picked) = await world.PickUpFurniAsync("owner", item.Id);
            Assert.Equal("block_red", picked.Type);
            Assert.True(room.Walkable[3, 3]);
        }

        [Fact]
        public async Task PlacementRules()
        {
            var (world, _, _) = await WorldWithRoom();
            await Assert.ThrowsAsync<WorldException>(() => world.PlaceFurniAsync("guest", "chair", 3, 3, "se"));
            await Assert.ThrowsAsync<WorldException>(() => world.PlaceFurniAsync("owner", "chair", 0, 7, "se")); // door
            await Assert.ThrowsAsync<WorldException>(() => world.PlaceFurniAsync("owner", "chair", 30, 30, "se"));
            await Assert.ThrowsAsync<WorldException>(() => world.PlaceFurniAsync("owner", "whiteboard", 3, 3, "se"));

            await world.PlaceFurniAsync("owner", "rug", 3, 3, "se");
            await world.PlaceFurniAsync("owner", "chair", 3, 3, "se"); // a chair can go on a rug
            await Assert.ThrowsAsync<WorldException>(() => world.PlaceFurniAsync("owner", "plant", 3, 3, "se"));

            // Can't drop a blocking item on someone.
            world.Move("guest", 5, 5);
            await Assert.ThrowsAsync<WorldException>(() => world.PlaceFurniAsync("owner", "teddy", 5, 5, "se"));
        }

        [Fact]
        public async Task SittingOnChairsAndFloorAndDancing()
        {
            var (world, _, _) = await WorldWithRoom();
            var (_, sat) = world.SetSitting("guest", true);
            Assert.True(sat.SittingOnFloor);

            var (_, dancing) = world.SetDance("guest", 3);
            Assert.Equal(3, dancing.Dance);
            Assert.False(dancing.SittingOnFloor);

            world.Move("guest", 4, 4);
            Assert.Equal(0, world.RoomOf("guest")!.Occupants["guest"].Dance);
        }

        [Fact]
        public async Task WhispersReachOnlyTargetSenderAndHosts()
        {
            var (world, _, roomId) = await WorldWithRoom();
            var third = new PlayerInfo(Guid.NewGuid(), "Cara D.", false, AvatarLook.Default);
            world.Join("third", third, roomId);

            var (message, recipients) = world.Whisper("guest", "third", "psst gago");
            Assert.Equal("psst ****", message.Text);
            Assert.Equal("Cara D.", message.WhisperTo);
            Assert.Equal(new[] { "guest", "owner", "third" }, recipients.OrderBy(r => r));

            // Whispers aren't shown to people who join later.
            var late = new PlayerInfo(Guid.NewGuid(), "Dan E.", false, AvatarLook.Default);
            var (snapshot, _, _) = world.Join("late", late, roomId);
            Assert.DoesNotContain(snapshot.Chat, m => m.WhisperTo != null);
        }

        [Fact]
        public async Task OwnerCanBanAndUnban()
        {
            var (world, _, roomId) = await WorldWithRoom();
            await Assert.ThrowsAsync<WorldException>(() => world.KickAsync("guest", "owner", true));

            await world.KickAsync("owner", "guest", ban: true);
            Assert.Null(world.RoomOf("guest"));
            var ex = Assert.Throws<WorldException>(() => world.Join("guest", Guest, roomId));
            Assert.Contains("banned", ex.Message);

            await world.UnbanAsync("owner", Guest.UserId);
            world.Join("guest", Guest, roomId);
        }

        [Fact]
        public async Task RoomFinderTabsAndSearch()
        {
            var (world, _, roomId) = await WorldWithRoom();
            await world.CreateRoomAsync(Teacher, new CreateRoomRequest("Secret Class", "", RoomKind.Classroom, "classroom"));

            Assert.Contains(world.ListRooms(Guest.UserId, "public"), r => r.Id == roomId);
            Assert.Contains(world.ListRooms(Guest.UserId, "popular"), r => r.Id == roomId);
            Assert.DoesNotContain(world.ListRooms(Guest.UserId, "popular"), r => r.Id == "library");
            var mine = Assert.Single(world.ListRooms(Owner.UserId, "mine"));
            Assert.True(mine.IsYours);

            Assert.Contains(world.ListRooms(Guest.UserId, "public", "hangout"), r => r.Id == roomId);
            Assert.Contains(world.ListRooms(Guest.UserId, "public", "ana"), r => r.Id == roomId);
            Assert.Empty(world.ListRooms(Guest.UserId, "public", "secret"));
        }

        [Fact]
        public async Task OwnerUpdatesSettingsAndDeletesRoom()
        {
            var (world, store, roomId) = await WorldWithRoom();
            await Assert.ThrowsAsync<WorldException>(() =>
                world.UpdateSettingsAsync("guest", new RoomSettingsRequest("Mine now", "", RoomKind.Public, 10)));
            await Assert.ThrowsAsync<WorldException>(() =>
                world.UpdateSettingsAsync("owner", new RoomSettingsRequest("Class", "", RoomKind.Classroom, 10)));

            var room = await world.UpdateSettingsAsync("owner", new RoomSettingsRequest("Ana's Study Den", "Quiet please", RoomKind.Private, 99));
            Assert.Equal("Ana's Study Den", room.Definition.Name);
            Assert.Equal(50, room.Definition.MaxUsers);
            Assert.DoesNotContain(world.ListRooms(Guest.UserId, "public"), r => r.Id == roomId);

            await world.PlaceFurniAsync("owner", "sofa", 2, 2, "se");
            var (_, occupants, furni) = await world.DeleteRoomAsync("owner");
            Assert.Equal(new[] { "guest", "owner" }, occupants.OrderBy(o => o));
            Assert.Contains("sofa", furni);
            Assert.Contains("plant", furni);
            Assert.Null(world.RoomOf("guest"));
            Assert.Empty(await store.LoadRoomsAsync());
        }

        [Fact]
        public async Task SpamClickingDoesNotWalkFaster()
        {
            var (world, _, _) = await WorldWithRoom();
            var start = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var now = start;
            world.Clock = () => now;
            var room = world.RoomOf("guest")!;
            var occupant = room.Occupants["guest"];

            // Walk from the door (0,7) toward (7,7), clicking the same target every 0.1 s for 2 s.
            for (var i = 0; i <= 20; i++)
            {
                now = start.AddSeconds(i * 0.1);
                world.Move("guest", 7, 7);
            }
            now = start.AddSeconds(2);
            var (x, _) = occupant.PositionAt(now);
            // One tile per 0.45 s: at most ceil(2 / 0.45) = 5 tiles in 2 seconds.
            Assert.InRange(x, 4, 5);
        }

        [Fact]
        public async Task EmotesAreLimitedToTheEmojiList()
        {
            var (world, _, _) = await WorldWithRoom();
            world.CheckEmote("guest", "❤️");
            Assert.Throws<WorldException>(() => world.CheckEmote("guest", "<script>"));
        }

        [Fact]
        public async Task OnlyHostsAndAllowedPeopleDrawOnTheBoard()
        {
            var (world, _, _) = await WorldWithRoom(); // the owner and a guest are already inside
            var ex = Assert.Throws<WorldException>(() => world.UpdateBoard("guest", "{}", ""));
            Assert.Contains("teacher", ex.Message);
            world.UpdateBoard("owner", "{\"elements\":[]}", "data:image/png;base64,AAAA");
            Assert.Throws<WorldException>(() => world.SetBoardAccess("guest", true));
            world.AllowBoardDrawer("owner", "guest", true);
            world.UpdateBoard("guest", "{\"elements\":[1]}", "javascript:alert(1)");
            var room = world.RoomOf("guest")!;
            Assert.Equal("{\"elements\":[1]}", room.BoardScene);
            Assert.Equal(string.Empty, room.BoardPreview); // not an image, so dropped
            world.AllowBoardDrawer("owner", "guest", false);
            Assert.Throws<WorldException>(() => world.UpdateBoard("guest", "{}", ""));
            world.SetBoardAccess("owner", true);
            world.UpdateBoard("guest", "{}", "");
            world.ClearBoard("owner");
            Assert.Equal(string.Empty, room.BoardScene);
        }
    }
}
