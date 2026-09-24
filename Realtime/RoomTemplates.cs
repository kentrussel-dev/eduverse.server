namespace EduVerse.Server.Realtime
{
    /// <summary>Furniture rules and the ready-made room layouts rooms are created from.</summary>
    public static class RoomTemplates
    {
        // Furni that avatars cannot walk through.
        private static readonly HashSet<string> Blocking = new()
        {
            "desk", "teacher_desk", "table", "bookshelf", "plant", "computer", "locker",
            "lamp", "teddy", "aquarium", "tv", "arcade", "trophy",
            "block_red", "block_blue", "block_yellow", "block_green"
        };

        // Furni that avatars sit on when they stop on it.
        private static readonly HashSet<string> Seats = new() { "chair", "sofa", "stool", "beanbag" };

        public static readonly IReadOnlyList<string> Names = new[] { "classroom", "study_hall", "lounge", "empty" };

        public static bool IsBlocking(string type) => Blocking.Contains(type);
        public static bool IsSeat(string type) => Seats.Contains(type);

        public static RoomDefinition Create(string template)
        {
            return template switch
            {
                "classroom" => Classroom(),
                "study_hall" => StudyHall(),
                "lounge" => Lounge(),
                _ => Empty()
            };
        }

        public static List<RoomDefinition> BuiltInRooms()
        {
            var lobby = Lounge();
            lobby.Id = "lobby";
            lobby.Name = "Main Hall";
            lobby.Description = "Meet classmates from every school.";
            lobby.Kind = RoomKind.Lobby;
            lobby.MaxUsers = 50;

            var library = StudyHall();
            library.Id = "library";
            library.Name = "Quiet Library";
            library.Description = "Study together. Keep chat on-topic.";
            library.Kind = RoomKind.Study;

            var classroom = Classroom();
            classroom.Id = "classroom-101";
            classroom.Name = "Classroom 101";
            classroom.Description = "Open classroom any teacher can run.";
            classroom.Kind = RoomKind.Classroom;

            foreach (var room in new[] { lobby, library, classroom })
            {
                room.BuiltIn = true;
                room.OwnerName = "EduVerse";
            }
            return new List<RoomDefinition> { lobby, library, classroom };
        }

        private static List<string> Grid(int width, int depth)
        {
            return Enumerable.Range(0, depth).Select(_ => new string('0', width)).ToList();
        }

        private static RoomDefinition Classroom()
        {
            var room = new RoomDefinition { Layout = Grid(12, 11), DoorX = 0, DoorY = 10, MaxUsers = 35 };
            var f = room.Furni;
            f.Add(new FurniItem { Type = "whiteboard", X = 3, Y = 0, Dir = "sw" });
            f.Add(new FurniItem { Type = "teacher_desk", X = 5, Y = 1, Dir = "sw" });
            f.Add(new FurniItem { Type = "teacher_desk", X = 6, Y = 1, Dir = "sw" });
            f.Add(new FurniItem { Type = "chair", X = 6, Y = 0, Dir = "sw" });
            foreach (var deskRow in new[] { 3, 6 })
            {
                foreach (var x in new[] { 2, 3, 5, 6, 8, 9 })
                {
                    f.Add(new FurniItem { Type = "desk", X = x, Y = deskRow, Dir = "ne" });
                    f.Add(new FurniItem { Type = "chair", X = x, Y = deskRow + 1, Dir = "ne" });
                }
            }
            f.Add(new FurniItem { Type = "bookshelf", X = 0, Y = 1, Dir = "se" });
            f.Add(new FurniItem { Type = "bookshelf", X = 0, Y = 2, Dir = "se" });
            f.Add(new FurniItem { Type = "plant", X = 0, Y = 0, Dir = "se" });
            f.Add(new FurniItem { Type = "plant", X = 11, Y = 0, Dir = "sw" });
            f.Add(new FurniItem { Type = "locker", X = 0, Y = 5, Dir = "se" });
            f.Add(new FurniItem { Type = "locker", X = 0, Y = 6, Dir = "se" });
            return room;
        }

        private static RoomDefinition StudyHall()
        {
            var room = new RoomDefinition { Layout = Grid(14, 12), DoorX = 0, DoorY = 11 };
            var f = room.Furni;
            for (var x = 1; x < 13; x += 2)
            {
                f.Add(new FurniItem { Type = "bookshelf", X = x, Y = 0, Dir = "sw" });
            }
            for (var y = 1; y < 9; y += 2)
            {
                f.Add(new FurniItem { Type = "bookshelf", X = 0, Y = y, Dir = "se" });
            }
            foreach (var (tx, ty) in new[] { (4, 4), (9, 4), (4, 8), (9, 8) })
            {
                f.Add(new FurniItem { Type = "table", X = tx, Y = ty });
                f.Add(new FurniItem { Type = "table", X = tx + 1, Y = ty });
                f.Add(new FurniItem { Type = "chair", X = tx, Y = ty - 1, Dir = "sw" });
                f.Add(new FurniItem { Type = "chair", X = tx + 1, Y = ty - 1, Dir = "sw" });
                f.Add(new FurniItem { Type = "chair", X = tx, Y = ty + 1, Dir = "ne" });
                f.Add(new FurniItem { Type = "chair", X = tx + 1, Y = ty + 1, Dir = "ne" });
            }
            f.Add(new FurniItem { Type = "computer", X = 12, Y = 10 });
            f.Add(new FurniItem { Type = "stool", X = 12, Y = 9, Dir = "se" });
            f.Add(new FurniItem { Type = "plant", X = 13, Y = 0 });
            return room;
        }

        private static RoomDefinition Lounge()
        {
            var room = new RoomDefinition
            {
                Layout = new List<string>
                {
                    "xxxx000000000000",
                    "xxxx000000000000",
                    "xxxx000000000000",
                    "xxxx000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                    "0000000000000000",
                },
                DoorX = 0,
                DoorY = 13,
                MaxUsers = 40
            };
            var f = room.Furni;
            f.Add(new FurniItem { Type = "rug", X = 8, Y = 6 });
            f.Add(new FurniItem { Type = "rug", X = 9, Y = 6 });
            f.Add(new FurniItem { Type = "rug", X = 8, Y = 7 });
            f.Add(new FurniItem { Type = "rug", X = 9, Y = 7 });
            foreach (var x in new[] { 7, 8, 9, 10 })
            {
                f.Add(new FurniItem { Type = "sofa", X = x, Y = 4, Dir = "sw" });
                f.Add(new FurniItem { Type = "sofa", X = x, Y = 9, Dir = "ne" });
            }
            foreach (var (px, py) in new[] { (4, 0), (15, 0), (0, 4), (15, 13), (6, 4), (11, 9) })
            {
                f.Add(new FurniItem { Type = "plant", X = px, Y = py });
            }
            f.Add(new FurniItem { Type = "table", X = 2, Y = 8 });
            f.Add(new FurniItem { Type = "stool", X = 1, Y = 8, Dir = "se" });
            f.Add(new FurniItem { Type = "stool", X = 3, Y = 8, Dir = "nw" });
            f.Add(new FurniItem { Type = "bookshelf", X = 12, Y = 0, Dir = "sw" });
            f.Add(new FurniItem { Type = "bookshelf", X = 13, Y = 0, Dir = "sw" });
            return room;
        }

        private static RoomDefinition Empty()
        {
            var room = new RoomDefinition { Layout = Grid(8, 8), DoorX = 0, DoorY = 7 };
            room.Furni.Add(new FurniItem { Type = "plant", X = 7, Y = 0 });
            return room;
        }
    }
}
