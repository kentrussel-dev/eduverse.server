using EduVerse.Server.Realtime;

namespace EduVerse.Server.Tests
{
    public class PathfinderTests
    {
        private static bool[,] OpenGrid(int width, int depth)
        {
            var grid = new bool[width, depth];
            for (var x = 0; x < width; x++)
                for (var y = 0; y < depth; y++)
                    grid[x, y] = true;
            return grid;
        }

        [Fact]
        public void WalksDiagonallyAcrossOpenFloor()
        {
            var path = Pathfinder.FindPath(OpenGrid(5, 5), (0, 0), (3, 3));
            Assert.Equal(new List<(int, int)> { (1, 1), (2, 2), (3, 3) }, path);
        }

        [Fact]
        public void RoutesAroundWallsWithoutCuttingCorners()
        {
            var grid = OpenGrid(3, 3);
            grid[1, 0] = false;
            grid[1, 1] = false;
            var path = Pathfinder.FindPath(grid, (0, 0), (2, 0));

            Assert.Equal((2, 0), path[^1]);
            Assert.DoesNotContain((1, 0), path);
            Assert.DoesNotContain((1, 1), path);
            Assert.Contains((1, 2), path);
        }

        [Fact]
        public void ReturnsEmptyForBlockedOrUnreachableGoals()
        {
            var grid = OpenGrid(3, 3);
            grid[2, 2] = false;
            Assert.Empty(Pathfinder.FindPath(grid, (0, 0), (2, 2)));
            Assert.Empty(Pathfinder.FindPath(grid, (0, 0), (9, 9)));
            Assert.Empty(Pathfinder.FindPath(grid, (1, 1), (1, 1)));
        }
    }

    public class ChatFilterTests
    {
        [Theory]
        [InlineData("you are so gago", "you are so ****")]
        [InlineData("SHIT happens", "**** happens")]
        [InlineData("f.u.c.k is fine but fuk is not", "f.u.c.k is fine but *** is not")]
        [InlineData("tang ina mo", "**** *** mo")]
        [InlineData("sh1t", "****")]
        public void MasksBadWords(string input, string expected)
        {
            var result = ChatFilter.Clean(input);
            Assert.Equal(expected, result.Text);
            Assert.True(result.WasFiltered);
        }

        [Theory]
        [InlineData("add me on discord.gg/abc")]
        [InlineData("my email is kid@example.com")]
        [InlineData("text me 0917 123 4567")]
        [InlineData("go to https://example.org now")]
        public void HidesPersonalInfoAndLinks(string input)
        {
            var result = ChatFilter.Clean(input);
            Assert.Contains("[hidden]", result.Text);
            Assert.True(result.WasFiltered);
        }

        [Theory]
        [InlineData("What is 12 x 12?")]
        [InlineData("Let's study Grade 5 science together")]
        [InlineData("I scored 100 on the quiz")]
        public void LeavesNormalMessagesAlone(string input)
        {
            var result = ChatFilter.Clean(input);
            Assert.Equal(input, result.Text);
            Assert.False(result.WasFiltered);
        }

        [Fact]
        public void TrimsAndLimitsLength()
        {
            var result = ChatFilter.Clean("  hello   there  " + new string('a', 500));
            Assert.StartsWith("hello there ", result.Text);
            Assert.Equal(ChatFilter.MaxLength, result.Text.Length);
        }
    }

    public class WorldStateTests
    {
        private static readonly PlayerInfo Teacher = new(Guid.NewGuid(), "Ms. Cruz", true, AvatarLook.Default);
        private static readonly PlayerInfo Student = new(Guid.NewGuid(), "Juan D.", false, AvatarLook.Default);

        private static async Task<WorldState> NewWorld()
        {
            var world = new WorldState(new InMemoryRoomStore());
            await world.EnsureLoadedAsync();
            return world;
        }

        [Fact]
        public async Task BuiltInRoomsAreListed()
        {
            var world = await NewWorld();
            var ids = world.ListRooms(Student.UserId).Select(r => r.Id).ToList();
            Assert.Contains("lobby", ids);
            Assert.Contains("library", ids);
            Assert.Contains("classroom-101", ids);
        }

        [Fact]
        public async Task JoinPlacesAvatarAtDoorAndMovingLeavesPreviousRoom()
        {
            var world = await NewWorld();
            var (snapshot, you, left) = world.Join("c1", Student, "lobby");
            Assert.Null(left);
            Assert.Equal((snapshot.DoorX, snapshot.DoorY), (you.X, you.Y));

            var (_, _, leftId) = world.Join("c1", Student, "library");
            Assert.Equal("lobby", leftId);
            Assert.Equal("library", world.RoomOf("c1")!.Id);
        }

        [Fact]
        public async Task PositionFollowsWalkOverTime()
        {
            var world = await NewWorld();
            var now = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            world.Clock = () => now;
            world.Join("c1", Student, "lobby");

            var moved = world.Move("c1", 3, 20);
            Assert.NotNull(moved);
            var path = moved!.Value.Path;
            Assert.Equal(new[] { 0, 23 }, path[0]);
            Assert.Equal(new[] { 3, 20 }, path[^1]);

            var occupant = world.RoomOf("c1")!.Occupants["c1"];
            Assert.Equal((0, 23), occupant.PositionAt(now));
            Assert.Equal((3, 20), occupant.PositionAt(now.AddSeconds(10)));

            // Someone arriving mid-walk gets the rest of the walk.
            var dto = world.RoomOf("c1")!.ToDto(occupant, now.AddSeconds(0.5));
            Assert.Equal((2, 21), (dto.X, dto.Y));
            Assert.Equal(new[] { new[] { 3, 20 } }, dto.WalkingTo);
            Assert.Empty(world.RoomOf("c1")!.ToDto(occupant, now.AddSeconds(10)).WalkingTo);
        }

        [Fact]
        public async Task CannotWalkOntoDesks()
        {
            var world = await NewWorld();
            world.Join("c1", Student, "classroom-101");
            Assert.Null(world.Move("c1", 2, 3));
            Assert.NotNull(world.Move("c1", 2, 4)); // the chair behind the desk
        }

        [Fact]
        public async Task ChatIsFilteredAndRateLimited()
        {
            var world = await NewWorld();
            world.Join("c1", Student, "lobby");

            var (_, message) = world.Say("c1", "hello gago");
            Assert.Equal("hello ****", message.Text);

            for (var i = 0; i < 4; i++)
            {
                world.Say("c1", "hi " + i);
            }
            var ex = Assert.Throws<WorldException>(() => world.Say("c1", "one more"));
            Assert.Contains("Slow down", ex.Message);
        }

        [Fact]
        public async Task OnlyTeachersCreateClassroomsAndOthersJoinByCode()
        {
            var world = await NewWorld();
            await Assert.ThrowsAsync<WorldException>(() =>
                world.CreateRoomAsync(Student, new CreateRoomRequest("Math 5", "", RoomKind.Classroom, "classroom")));

            var room = await world.CreateRoomAsync(Teacher, new CreateRoomRequest("Math 5 - Rizal", "Fractions", RoomKind.Classroom, "classroom"));
            Assert.Equal(6, room.Id.Length);
            Assert.DoesNotContain(world.ListRooms(Student.UserId), r => r.Id == room.Id);
            Assert.Contains(world.ListRooms(Teacher.UserId, "mine"), r => r.Id == room.Id);

            var (snapshot, _, _) = world.Join("student", Student, room.Id.ToLowerInvariant());
            Assert.False(snapshot.YouAreHost);
            var (teacherSnapshot, _, _) = world.Join("teacher", Teacher, room.Id);
            Assert.True(teacherSnapshot.YouAreHost);
        }

        [Fact]
        public async Task HostToolsAreHostOnly()
        {
            var world = await NewWorld();
            world.Join("teacher", Teacher, "classroom-101");
            world.Join("student", Student, "classroom-101");

            Assert.Throws<WorldException>(() => world.SetQuietMode("student", true));
            Assert.Throws<WorldException>(() => world.SetMuted("student", "teacher", true));

            world.SetQuietMode("teacher", true);
            var ex = Assert.Throws<WorldException>(() => world.Say("student", "hello"));
            Assert.Contains("Quiet mode", ex.Message);
            world.Say("teacher", "Open your books to page 10.");

            world.SetQuietMode("teacher", false);
            world.SetMuted("teacher", "student", true);
            Assert.Throws<WorldException>(() => world.Say("student", "hello"));

            var (_, text) = world.SetWhiteboard("teacher", "Homework: page 10");
            Assert.Equal("Homework: page 10", text);
        }

        [Fact]
        public async Task ReportsAreSavedWithRecentChat()
        {
            var store = new InMemoryRoomStore();
            var world = new WorldState(store);
            await world.EnsureLoadedAsync();
            world.Join("a", Student, "lobby");
            world.Join("b", Teacher, "lobby");
            world.Say("b", "hello");

            await world.ReportAsync("a", "b", "rude");

            var report = Assert.Single(store.Reports);
            Assert.Equal(Teacher.UserId, report.TargetUserId);
            Assert.Single(report.RecentChat);
        }

        [Theory]
        [InlineData("Juan Dela Cruz", null, "Juan C.")]
        [InlineData("Maria", null, "Maria")]
        [InlineData("", "student.one@school.edu", "student.one")]
        [InlineData("kid@example.com", "kid@example.com", "kid")]
        public void DisplayNamesHideFullNames(string fullName, string? email, string expected)
        {
            Assert.Equal(expected, WorldHub.DisplayName(fullName, email));
        }
    }
}
