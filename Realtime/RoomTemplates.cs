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

        public static readonly IReadOnlyList<string> Names =
            new[] { "apartment", "house", "classroom", "study_hall", "lounge", "empty" }.Concat(ShapeList().Select(s => s.Id)).ToList();

        /// <summary>An empty room shape to build in (free, like Habbo's room layouts).</summary>
        public record RoomShape(string Id, string Name, List<string> Layout, int DoorX, int DoorY)
        {
            public int Tiles => Layout.Sum(r => r.Count(c => c != 'x'));
        }

        private static RoomShape Shape(string id, string name, int w, int d, Func<int, int, bool> floor, int? doorY = null)
        {
            var layout = Enumerable.Range(0, d).Select(y => new string(Enumerable.Range(0, w).Select(x => floor(x, y) ? '0' : 'x').ToArray())).ToList();
            var door = doorY ?? Enumerable.Range(0, d).Last(y => layout[y][0] == '0');
            return new RoomShape(id, name, layout, 0, door);
        }

        private static List<RoomShape>? _shapes;

        /// <summary>Empty room shapes of different sizes.</summary>
        public static List<RoomShape> ShapeList() => _shapes ??= new List<RoomShape>
        {
            Shape("shape_tiny", "Tiny", 6, 6, (x, y) => true),
            Shape("shape_small", "Small", 8, 8, (x, y) => true),
            Shape("shape_medium", "Medium", 10, 10, (x, y) => true),
            Shape("shape_wide", "Wide", 16, 8, (x, y) => true),
            Shape("shape_long", "Long hall", 6, 18, (x, y) => true),
            Shape("shape_large", "Large", 14, 14, (x, y) => true),
            Shape("shape_huge", "Huge", 20, 20, (x, y) => true),
            Shape("shape_giant", "Giant", 28, 26, (x, y) => true),
            Shape("shape_l", "L-shape", 14, 14, (x, y) => !(x >= 7 && y < 7)),
            Shape("shape_u", "U-shape", 14, 12, (x, y) => !(x >= 5 && x <= 8 && y < 7)),
            Shape("shape_t", "T-shape", 15, 13, (x, y) => y < 5 || (x >= 5 && x <= 9), 2),
            Shape("shape_cross", "Cross", 15, 15, (x, y) => (x >= 5 && x <= 9) || (y >= 5 && y <= 9), 7),
            Shape("shape_courtyard", "Courtyard", 14, 14, (x, y) => !(x >= 5 && x <= 8 && y >= 5 && y <= 8)),
            Shape("shape_ring", "Ring", 16, 16, (x, y) => x < 4 || y < 4 || x > 11 || y > 11),
            Shape("shape_steps", "Steps", 16, 16, (x, y) => x + y >= 6 && x + y <= 24 && Math.Abs(x - y) <= 9),
            Shape("shape_zigzag", "Zigzag", 18, 12, (x, y) => (x / 6) % 2 == 0 ? y >= 3 : y < 9),
        };

        public static bool IsBlocking(string type) =>
            Blocking.Contains(type) || Catalog.Asset(type) is { Seat: false, Walk: false };
        public static bool IsSeat(string type) => Seats.Contains(type) || Catalog.Asset(type)?.Seat == true;
        /// <summary>Flat things (rugs) other furniture can stand on.</summary>
        public static bool IsRug(string type) => type == "rug" || Catalog.Asset(type)?.Walk == true;

        public static RoomDefinition Create(string template)
        {
            var shape = ShapeList().FirstOrDefault(s => s.Id == template);
            if (shape != null)
            {
                return new RoomDefinition { Layout = shape.Layout.ToList(), DoorX = shape.DoorX, DoorY = shape.DoorY, MaxUsers = Math.Clamp(shape.Tiles / 4, 15, 75) };
            }
            return template switch
            {
                "classroom" => Classroom(),
                "study_hall" => StudyHall(),
                "lounge" => Lounge(),
                "apartment" => Apartment(),
                "house" => House(),
                _ => Empty()
            };
        }

        public static List<RoomDefinition> BuiltInRooms()
        {
            var lobby = MainHall();
            lobby.Id = "lobby";
            lobby.Name = "Main Hall";
            lobby.Description = "Meet classmates from every school.";
            lobby.Kind = RoomKind.Lobby;
            lobby.MaxUsers = 75;

            var library = Library();
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
            f.Add(new FurniItem { Type = "plant", X = 0, Y = 0 });
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

        // ---- rooms furnished with the 3D-kit furniture ----

        private static void Add(RoomDefinition room, string type, int x, int y, string dir = "se") =>
            room.Furni.Add(new FurniItem { Type = type, X = x, Y = y, Dir = dir });

        /// <summary>A table with a chair on each side, every chair facing the table.</summary>
        private static void TableWithChairs(RoomDefinition room, string table, string chair, int x, int y)
        {
            Add(room, table, x, y);
            Add(room, chair, x - 1, y, "se");
            Add(room, chair, x + 1, y, "nw");
            Add(room, chair, x, y - 1, "sw");
            Add(room, chair, x, y + 1, "ne");
        }

        /// <summary>Rugs spread over an area, two tiles apart so they don't pile up.</summary>
        private static void Rugs(RoomDefinition room, string rug, int x0, int y0, int x1, int y1)
        {
            for (var x = x0 + (x1 - x0) % 2 / 2; x <= x1; x += 2)
            {
                for (var y = y0 + (y1 - y0) % 2 / 2; y <= y1; y += 2)
                {
                    Add(room, rug, x, y);
                }
            }
        }

        /// <summary>The Main Hall: a big lobby with a lounge, a cafe, a snack bar, a games corner and a study corner.</summary>
        private static RoomDefinition MainHall()
        {
            var room = new RoomDefinition { Layout = Grid(26, 24), DoorX = 0, DoorY = 23, MaxUsers = 75 };

            // Back walls: bookcases, plants and a TV.
            foreach (var x in new[] { 3, 4, 5, 6 })
            {
                Add(room, "k_bookcaseOpen", x, 0, "sw");
            }
            Add(room, "k_pottedPlant", 0, 0);
            Add(room, "kf_cactus_medium_a", 8, 0, "sw");
            Add(room, "kf_lamp_standing", 2, 0, "sw");
            Add(room, "kf_lamp_standing", 0, 2);

            // Lounge (top left).
            Rugs(room, "kf_rug_rectangle_stripes_a", 2, 3, 6, 6);
            foreach (var x in new[] { 3, 4, 5 })
            {
                Add(room, "kf_couch_pillows", x, 2, "sw");
                Add(room, "k_loungeSofa", x, 7, "ne");
            }
            Add(room, "k_tableCoffee", 4, 4);
            Add(room, "k_tableCoffeeGlass", 4, 5);
            Add(room, "kf_armchair", 1, 4, "se");
            Add(room, "kf_armchair", 1, 5, "se");
            Add(room, "k_televisionModern", 7, 4, "nw");

            // Cafe (top right): round tables with chairs.
            Rugs(room, "kf_rug_rectangle_a", 13, 2, 22, 9);
            foreach (var (tx, ty) in new[] { (14, 3), (18, 3), (22, 3), (14, 7), (18, 7), (22, 7) })
            {
                TableWithChairs(room, "kr_table_round_a_small_decorated", "kr_chair_a", tx, ty);
            }

            // Snack bar along the right side.
            for (var y = 11; y <= 16; y++)
            {
                Add(room, y == 13 ? "kr_kitchencounter_sink" : "kr_kitchencounter_straight_a_decorated", 25, y, "nw");
                Add(room, "k_stoolBar", 23, y, "se");
            }
            Add(room, "kr_fridge_a_decorated", 25, 10, "nw");
            Add(room, "kr_fridge_b", 25, 9, "nw");
            Add(room, "k_kitchenCoffeeMachine", 25, 17, "nw");

            // Central plaza.
            Rugs(room, "k_rugRound", 11, 11, 14, 14);
            Add(room, "kr_pillar_a", 10, 10);
            Add(room, "kr_pillar_a", 15, 10);
            Add(room, "kr_pillar_a", 10, 15);
            Add(room, "kr_pillar_a", 15, 15);
            foreach (var x in new[] { 11, 12, 13, 14 })
            {
                Add(room, "k_benchCushion", x, 10, "sw");
                Add(room, "k_benchCushion", x, 15, "ne");
            }
            Add(room, "k_pottedPlant", 12, 12);
            Add(room, "k_pottedPlant", 13, 13);

            // Games corner (bottom right).
            Rugs(room, "kf_rug_oval_b", 17, 18, 22, 22);
            Add(room, "tv", 20, 17, "sw");
            Add(room, "arcade", 18, 17, "sw");
            Add(room, "arcade", 22, 17, "sw");
            foreach (var (bx, by) in new[] { (18, 20), (20, 20), (22, 20) })
            {
                Add(room, "beanbag", bx, by, "ne");
            }
            Add(room, "k_speaker", 17, 17, "sw");
            Add(room, "k_speaker", 23, 17, "sw");
            Add(room, "k_loungeChairRelax", 24, 21, "nw");

            // Study corner (bottom left).
            foreach (var y in new[] { 12, 15, 18 })
            {
                foreach (var x in new[] { 2, 4, 6 })
                {
                    Add(room, "k_desk", x, y, "sw");
                    Add(room, "k_chairDesk", x, y - 1, "sw");
                }
            }
            Add(room, "k_bookcaseClosedWide", 0, 12);
            Add(room, "k_bookcaseClosedWide", 0, 15);
            Add(room, "k_bookcaseClosedWide", 0, 18);

            // Plants around the edges.
            foreach (var (px, py) in new[] { (9, 0), (12, 0), (25, 0), (25, 5), (25, 22), (8, 22), (16, 22), (0, 9), (9, 18) })
            {
                Add(room, py % 2 == 0 ? "k_pottedPlant" : "kf_cactus_medium_b", px, py);
            }
            Add(room, "k_trashcan", 9, 9);
            Add(room, "k_trashcan", 16, 16);
            return room;
        }

        /// <summary>A large library: shelves on the walls, reading tables, study desks and a reading nook.</summary>
        private static RoomDefinition Library()
        {
            var room = new RoomDefinition { Layout = Grid(22, 18), DoorX = 0, DoorY = 17, MaxUsers = 50 };
            for (var x = 1; x < 21; x++)
            {
                Add(room, x % 3 == 0 ? "kf_shelf_b_large_decorated" : "k_bookcaseClosedDoors", x, 0, "sw");
            }
            for (var y = 1; y < 15; y++)
            {
                Add(room, y % 3 == 0 ? "kf_shelf_b_large" : "k_bookcaseOpen", 0, y, "se");
            }
            // Reading tables.
            foreach (var ty in new[] { 4, 9 })
            {
                foreach (var tx in new[] { 4, 8, 12 })
                {
                    Add(room, "kf_table_medium", tx, ty);
                    Add(room, "kf_table_medium", tx + 1, ty);
                    Add(room, "kf_chair_a_wood", tx, ty - 1, "sw");
                    Add(room, "kf_chair_a_wood", tx + 1, ty - 1, "sw");
                    Add(room, "kf_chair_a_wood", tx, ty + 1, "ne");
                    Add(room, "kf_chair_a_wood", tx + 1, ty + 1, "ne");
                }
            }
            // Computer desks.
            for (var y = 3; y <= 11; y += 2)
            {
                Add(room, y % 4 == 1 ? "k_desk" : "k_deskCorner", 20, y, "nw");
                Add(room, "k_chairDesk", 19, y, "se");
            }
            // Reading nook.
            Rugs(room, "kf_rug_oval_a", 4, 13, 8, 15);
            foreach (var x in new[] { 4, 6, 8 })
            {
                Add(room, "kf_armchair_pillows", x, 13, "sw");
                Add(room, "k_lampRoundFloor", x + 1, 13, "sw");
            }
            Add(room, "k_tableCoffeeSquare", 6, 15);
            Add(room, "k_bear", 5, 15);
            // Quiet study carrels.
            foreach (var x in new[] { 12, 14, 16 })
            {
                Add(room, "k_deskCorner", x, 14, "sw");
                Add(room, "k_chairModernCushion", x, 13, "sw");
            }
            foreach (var (px, py) in new[] { (0, 0), (21, 0), (0, 16), (21, 16), (10, 16), (17, 6) })
            {
                Add(room, "k_pottedPlant", px, py);
            }
            Add(room, "kf_pictureframe_standing_a", 18, 16, "ne");
            Add(room, "k_trashcan", 11, 16);
            return room;
        }

        /// <summary>A furnished apartment: living room, kitchen, bedroom and bathroom.</summary>
        private static RoomDefinition Apartment()
        {
            var room = new RoomDefinition { Layout = Grid(14, 12), DoorX = 0, DoorY = 11, MaxUsers = 25 };
            // Kitchen along the back wall.
            Add(room, "k_kitchenFridgeLarge", 0, 0, "sw");
            Add(room, "k_kitchenCabinet", 1, 0, "sw");
            Add(room, "k_kitchenSink", 2, 0, "sw");
            Add(room, "k_kitchenStove", 3, 0, "sw");
            Add(room, "k_kitchenCabinetDrawer", 4, 0, "sw");
            TableWithChairs(room, "k_tableRound", "k_chairCushion", 3, 3);
            // Living room.
            Rugs(room, "k_rugRectangle", 7, 4, 10, 6);
            Add(room, "k_loungeSofa", 8, 3, "sw");
            Add(room, "k_loungeSofa", 9, 3, "sw");
            Add(room, "k_loungeChair", 7, 5, "se");
            Add(room, "k_tableCoffee", 8, 5);
            Add(room, "k_televisionModern", 8, 7, "ne");
            Add(room, "k_lampSquareFloor", 10, 3, "sw");
            Add(room, "k_pottedPlant", 6, 0, "sw");
            Add(room, "k_bookcaseOpen", 7, 0, "sw");
            Add(room, "k_bookcaseOpenLow", 8, 0, "sw");
            Add(room, "k_speaker", 9, 0, "sw");
            // Bedroom.
            Add(room, "kf_bed_double_a", 12, 1, "sw");
            Add(room, "k_sideTable", 13, 0, "sw");
            Add(room, "kf_cabinet_medium_decorated", 11, 0, "sw");
            Rugs(room, "kf_rug_oval_a", 11, 3, 12, 4);
            Add(room, "k_desk", 13, 5, "nw");
            Add(room, "k_chairDesk", 12, 5, "se");
            // Bathroom.
            Add(room, "k_bathtub", 13, 10, "nw");
            Add(room, "k_toilet", 13, 8, "nw");
            Add(room, "k_bathroomSink", 11, 11, "ne");
            Add(room, "k_rugDoormat", 12, 10);
            Add(room, "k_rugDoormat", 1, 11);
            Add(room, "kf_cactus_small_a", 0, 7);
            return room;
        }

        /// <summary>A bigger furnished house.</summary>
        private static RoomDefinition House()
        {
            var room = Apartment();
            room.Layout = Grid(18, 16);
            room.DoorX = 0;
            room.DoorY = 15;
            room.MaxUsers = 35;
            room.Furni.RemoveAll(f => f.Type == "k_rugDoormat" && f.X == 1 && f.Y == 11);
            // A second bedroom, a garden corner and a games room.
            Add(room, "kf_bed_single_a", 16, 1, "sw");
            Add(room, "kf_bed_single_b", 17, 3, "nw");
            Add(room, "k_sideTableDrawers", 17, 0, "sw");
            Add(room, "k_bear", 16, 3);
            Rugs(room, "kf_rug_rectangle_stripes_b", 15, 5, 17, 6);
            foreach (var (px, py) in new[] { (3, 15), (5, 15), (7, 15), (2, 12) })
            {
                Add(room, px % 2 == 0 ? "k_pottedPlant" : "kf_cactus_medium_a", px, py);
            }
            Add(room, "k_benchCushion", 3, 13, "ne");
            Add(room, "k_benchCushion", 4, 13, "ne");
            Rugs(room, "kf_rug_rectangle_b", 8, 11, 12, 14);
            Add(room, "arcade", 9, 10, "sw");
            Add(room, "arcade", 11, 10, "sw");
            Add(room, "k_loungeSofaLong", 10, 15, "ne");
            Add(room, "beanbag", 8, 13, "se");
            Add(room, "k_radio", 12, 12);
            Add(room, "k_washerDryerStacked", 17, 15, "nw");
            Add(room, "k_washer", 17, 14, "nw");
            Add(room, "k_rugDoormat", 1, 15);
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
