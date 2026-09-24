using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace EduVerse.Server.Realtime
{
    public record PlayerInfo(Guid UserId, string Name, bool IsTeacher, AvatarLook Look);

    /// <summary>Someone standing in a room. One per SignalR connection.</summary>
    public class Occupant
    {
        public const double StepSeconds = 0.45;

        public required string ConnectionId { get; init; }
        public required PlayerInfo Player { get; set; }
        public int X { get; set; }
        public int Y { get; set; }
        public List<(int X, int Y)> Path { get; set; } = new();
        public DateTime PathStartedAt { get; set; }
        public bool Muted { get; set; }
        public bool HandRaised { get; set; }

        /// <summary>0 when not dancing, otherwise the dance style (1-4).</summary>
        public int Dance { get; set; }
        public bool SittingOnFloor { get; set; }
        public Queue<DateTime> RecentChat { get; } = new();

        /// <summary>The tile the avatar is on (or walking onto) at <paramref name="now"/>.</summary>
        public (int X, int Y) PositionAt(DateTime now)
        {
            if (Path.Count == 0)
            {
                return (X, Y);
            }
            var steps = (int)Math.Ceiling((now - PathStartedAt).TotalSeconds / StepSeconds);
            return steps <= 0 ? (X, Y) : Path[Math.Min(steps, Path.Count) - 1];
        }

        /// <summary>When the avatar finishes stepping onto the tile returned by <see cref="PositionAt"/> (now if standing still).</summary>
        public DateTime CurrentStepEndsAt(DateTime now)
        {
            if (Path.Count == 0)
            {
                return now;
            }
            var steps = (int)Math.Ceiling((now - PathStartedAt).TotalSeconds / StepSeconds);
            if (steps > Path.Count)
            {
                return now;
            }
            var endsAt = PathStartedAt.AddSeconds(Math.Max(0, steps) * StepSeconds);
            return endsAt > now ? endsAt : now;
        }

        /// <summary>Tiles still to walk after the one returned by <see cref="PositionAt"/>, so people who arrive later see the walk finish.</summary>
        public List<(int X, int Y)> RemainingPath(DateTime now)
        {
            if (Path.Count == 0)
            {
                return new();
            }
            var steps = Math.Max(0, (int)Math.Ceiling((now - PathStartedAt).TotalSeconds / StepSeconds));
            return Path.Skip(steps).ToList();
        }

        /// <summary>The tile the avatar will end up on once it finishes walking.</summary>
        public (int X, int Y) Destination => Path.Count == 0 ? (X, Y) : Path[^1];
    }

    /// <summary>The live state of one room.</summary>
    public class RoomRuntime
    {
        public const int ChatHistorySize = 50;

        public RoomRuntime(RoomDefinition definition)
        {
            Definition = definition;
            foreach (var item in definition.Furni.Where(f => string.IsNullOrEmpty(f.Id)))
            {
                item.Id = NewFurniId();
            }
            Depth = definition.Layout.Count;
            Width = definition.Layout.Max(row => row.Length);
            Walkable = new bool[Width, Depth];
            RebuildGrid();
        }

        public object Sync { get; } = new();
        public RoomDefinition Definition { get; }
        public int Width { get; }
        public int Depth { get; }
        public bool[,] Walkable { get; }
        public Dictionary<(int X, int Y), FurniItem> Seats { get; } = new();
        public Dictionary<string, Occupant> Occupants { get; } = new();
        public LinkedList<ChatMessageDto> Chat { get; } = new();
        public string Whiteboard { get; set; } = string.Empty;
        public bool QuietMode { get; set; }

        public string Id => Definition.Id;

        public static string NewFurniId() => Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();

        public bool IsFloor(int x, int y) =>
            x >= 0 && y >= 0 && y < Depth && x < Definition.Layout[y].Length && Definition.Layout[y][x] != 'x';

        /// <summary>Recomputes which tiles can be walked on and which are seats after furniture changes.</summary>
        public void RebuildGrid()
        {
            Seats.Clear();
            for (var y = 0; y < Depth; y++)
            {
                for (var x = 0; x < Width; x++)
                {
                    Walkable[x, y] = IsFloor(x, y);
                }
            }
            foreach (var item in Definition.Furni)
            {
                if (item.X >= Width || item.Y >= Depth || item.X < 0 || item.Y < 0)
                {
                    continue;
                }
                if (RoomTemplates.IsBlocking(item.Type))
                {
                    Walkable[item.X, item.Y] = false;
                }
                if (RoomTemplates.IsSeat(item.Type))
                {
                    Seats[(item.X, item.Y)] = item;
                }
            }
        }

        /// <summary>The room's owner. Owners build, change settings, and ban.</summary>
        public bool IsOwner(PlayerInfo player) => Definition.OwnerId == player.UserId;

        /// <summary>Hosts can moderate: the room's owner, or any teacher in a built-in classroom.</summary>
        public bool IsHost(PlayerInfo player) =>
            IsOwner(player) || (Definition.BuiltIn && Definition.Kind == RoomKind.Classroom && player.IsTeacher);

        public OccupantDto ToDto(Occupant o, DateTime now)
        {
            var (x, y) = o.PositionAt(now);
            return new OccupantDto(o.ConnectionId, o.Player.UserId.ToString(), o.Player.Name, o.Player.IsTeacher,
                IsHost(o.Player), o.Player.Look, x, y, o.Muted, o.HandRaised, o.Dance, o.SittingOnFloor,
                o.RemainingPath(now).Select(p => new[] { p.X, p.Y }).ToList());
        }

        public RoomInfoDto Info() => new(Id, Definition.Name, Definition.Description, Definition.Kind,
            Definition.MaxUsers, Definition.Bans.ToList());

        public void AddChat(ChatMessageDto message)
        {
            Chat.AddLast(message);
            while (Chat.Count > ChatHistorySize)
            {
                Chat.RemoveFirst();
            }
        }
    }

    public class WorldException : Exception
    {
        public WorldException(string message) : base(message) { }
    }

    /// <summary>All live rooms and who is in them. Registered as a singleton.</summary>
    public class WorldState
    {
        public const int MaxRoomsPerOwner = 5;
        public const int MaxFurniPerRoom = 150;
        public const int MaxDance = 4;
        private const int ChatBurstLimit = 5;
        private static readonly TimeSpan ChatBurstWindow = TimeSpan.FromSeconds(6);

        private static readonly HashSet<string> Emotes = new()
        {
            "❤️", "😂", "😮", "😢", "👍", "👏", "🎉", "⭐", "🤔", "😴", "📚", "✅"
        };

        private readonly IRoomStore _store;
        private readonly ConcurrentDictionary<string, RoomRuntime> _rooms = new();
        private readonly ConcurrentDictionary<string, string> _roomByConnection = new();
        private readonly SemaphoreSlim _loadLock = new(1, 1);
        private bool _loaded;

        public WorldState(IRoomStore store)
        {
            _store = store;
        }

        public Func<DateTime> Clock { get; set; } = () => DateTime.UtcNow;

        public static bool IsEmote(string emoji) => Emotes.Contains(emoji);

        public async Task EnsureLoadedAsync()
        {
            if (_loaded)
            {
                return;
            }
            await _loadLock.WaitAsync();
            try
            {
                if (_loaded)
                {
                    return;
                }
                foreach (var room in RoomTemplates.BuiltInRooms())
                {
                    _rooms[room.Id] = new RoomRuntime(room);
                }
                foreach (var room in await _store.LoadRoomsAsync())
                {
                    _rooms.TryAdd(room.Id, new RoomRuntime(room));
                }
                _loaded = true;
            }
            finally
            {
                _loadLock.Release();
            }
        }

        public RoomRuntime? RoomOf(string connectionId) =>
            _roomByConnection.TryGetValue(connectionId, out var roomId) && _rooms.TryGetValue(roomId, out var room)
                ? room
                : null;

        private RoomRuntime CurrentRoom(string connectionId) =>
            RoomOf(connectionId) ?? throw new WorldException("You're not in a room.");

        // ---- room finder ----

        private static bool IsListed(RoomDefinition d) => d.BuiltIn || d.Kind is RoomKind.Public or RoomKind.Study;

        /// <summary>
        /// Rooms for the navigator. Tabs: "public" (listed rooms), "popular" (listed rooms with people in them),
        /// "mine" (rooms you own). Classrooms and private rooms are never listed to others; they join by code.
        /// </summary>
        public List<RoomSummaryDto> ListRooms(Guid userId, string tab = "public", string? query = null)
        {
            IEnumerable<RoomRuntime> rooms = tab switch
            {
                "mine" => _rooms.Values.Where(r => r.Definition.OwnerId == userId),
                "popular" => _rooms.Values.Where(r => IsListed(r.Definition) && CountOf(r) > 0),
                _ => _rooms.Values.Where(r => IsListed(r.Definition)),
            };
            if (!string.IsNullOrWhiteSpace(query))
            {
                var q = query.Trim();
                rooms = _rooms.Values
                    .Where(r => IsListed(r.Definition) || r.Definition.OwnerId == userId)
                    .Where(r => r.Definition.Name.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                r.Definition.OwnerName.Contains(q, StringComparison.OrdinalIgnoreCase) ||
                                string.Equals(r.Id, q, StringComparison.OrdinalIgnoreCase));
            }
            var list = rooms.Select(r => Summarize(r, userId));
            list = tab == "public" && string.IsNullOrWhiteSpace(query)
                ? list.OrderByDescending(r => r.Kind == RoomKind.Lobby).ThenByDescending(r => r.UserCount).ThenBy(r => r.Name)
                : list.OrderByDescending(r => r.UserCount).ThenBy(r => r.Name);
            return list.Take(100).ToList();
        }

        public List<RoomSummaryDto> ListOwnedRooms(Guid userId) =>
            _rooms.Values.Where(r => r.Definition.OwnerId == userId).Select(r => Summarize(r, userId)).ToList();

        private static int CountOf(RoomRuntime r)
        {
            lock (r.Sync)
            {
                return r.Occupants.Count;
            }
        }

        private static RoomSummaryDto Summarize(RoomRuntime r, Guid userId) =>
            new(r.Id, r.Definition.Name, r.Definition.Description, r.Definition.Kind, r.Definition.OwnerName,
                CountOf(r), r.Definition.MaxUsers, r.Definition.OwnerId == userId);

        // ---- creating and managing rooms ----

        private static (string Name, string Description) CleanNameAndDescription(string? name, string? description)
        {
            var cleanName = ChatFilter.Clean(name);
            if (cleanName.Text.Length < 3 || cleanName.Text.Length > 40)
            {
                throw new WorldException("Room names need 3 to 40 characters.");
            }
            if (cleanName.WasFiltered)
            {
                throw new WorldException("Please choose a different room name.");
            }
            var cleanDescription = ChatFilter.Clean(description).Text;
            return (cleanName.Text, cleanDescription.Length > 120 ? cleanDescription[..120] : cleanDescription);
        }

        private static void CheckKind(PlayerInfo owner, RoomKind kind)
        {
            if (kind == RoomKind.Lobby || !Enum.IsDefined(kind))
            {
                throw new WorldException("That room type can't be created.");
            }
            if (kind == RoomKind.Classroom && !owner.IsTeacher)
            {
                throw new WorldException("Only teachers can create classrooms.");
            }
        }

        public async Task<RoomDefinition> CreateRoomAsync(PlayerInfo owner, CreateRoomRequest request)
        {
            var (name, description) = CleanNameAndDescription(request.Name, request.Description);
            CheckKind(owner, request.Kind);
            if (ListOwnedRooms(owner.UserId).Count >= MaxRoomsPerOwner)
            {
                throw new WorldException($"You can own up to {MaxRoomsPerOwner} rooms.");
            }

            var template = RoomTemplates.Names.Contains(request.Template)
                ? request.Template
                : request.Kind == RoomKind.Classroom ? "classroom" : "empty";
            var room = RoomTemplates.Create(template);
            room.Id = NewRoomCode();
            room.Name = name;
            room.Description = description;
            room.Kind = request.Kind;
            room.OwnerId = owner.UserId;
            room.OwnerName = owner.Name;
            room.CreatedAt = DateTime.UtcNow;

            var runtime = new RoomRuntime(room);
            await _store.SaveRoomAsync(room);
            _rooms[room.Id] = runtime;
            return room;
        }

        private string NewRoomCode()
        {
            const string alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
            while (true)
            {
                var code = new string(Enumerable.Range(0, 6)
                    .Select(_ => alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]).ToArray());
                if (!_rooms.ContainsKey(code))
                {
                    return code;
                }
            }
        }

        private RoomRuntime RequireOwner(string connectionId)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                if (!room.Occupants.TryGetValue(connectionId, out var me) || !room.IsOwner(me.Player))
                {
                    throw new WorldException("Only the room's owner can do that.");
                }
            }
            return room;
        }

        public async Task<RoomRuntime> UpdateSettingsAsync(string connectionId, RoomSettingsRequest request)
        {
            var room = RequireOwner(connectionId);
            var (name, description) = CleanNameAndDescription(request.Name, request.Description);
            Occupant owner;
            lock (room.Sync)
            {
                owner = room.Occupants[connectionId];
            }
            CheckKind(owner.Player, request.Kind);
            if (room.Definition.Kind == RoomKind.Classroom && request.Kind != RoomKind.Classroom && !owner.Player.IsTeacher)
            {
                throw new WorldException("Only teachers can change a classroom.");
            }
            lock (room.Sync)
            {
                room.Definition.Name = name;
                room.Definition.Description = description;
                room.Definition.Kind = request.Kind;
                room.Definition.MaxUsers = Math.Clamp(request.MaxUsers, 2, 50);
            }
            await _store.SaveRoomAsync(room.Definition);
            return room;
        }

        /// <summary>Deletes the owner's current room. Returns who was inside and the furni to give back.</summary>
        public async Task<(string RoomId, List<string> Occupants, List<string> Furni)> DeleteRoomAsync(string connectionId)
        {
            var room = RequireOwner(connectionId);
            List<string> occupants;
            List<string> furni;
            lock (room.Sync)
            {
                occupants = room.Occupants.Keys.ToList();
                furni = room.Definition.Furni.Select(f => f.Type).Where(Catalog.IsFurniType).ToList();
                room.Occupants.Clear();
            }
            foreach (var connection in occupants)
            {
                _roomByConnection.TryRemove(connection, out _);
            }
            _rooms.TryRemove(room.Id, out _);
            await _store.DeleteRoomAsync(room.Id);
            return (room.Id, occupants, furni);
        }

        // ---- entering and leaving ----

        /// <summary>Puts the connection in a room at its door. Returns the snapshot and any room it left.</summary>
        public (RoomSnapshotDto Snapshot, OccupantDto You, string? LeftRoomId) Join(string connectionId, PlayerInfo player, string roomId)
        {
            if (!_rooms.TryGetValue(roomId.Trim().ToUpperInvariant(), out var room) &&
                !_rooms.TryGetValue(roomId.Trim(), out room))
            {
                throw new WorldException("That room doesn't exist. Check the room code.");
            }

            var left = RoomOf(connectionId);
            if (left == room)
            {
                throw new WorldException("You're already in this room.");
            }

            lock (room.Sync)
            {
                if (room.Definition.Bans.Any(b => b.UserId == player.UserId))
                {
                    throw new WorldException("You're banned from this room.");
                }
                if (room.Occupants.Count >= room.Definition.MaxUsers && !room.IsOwner(player))
                {
                    throw new WorldException("This room is full.");
                }
            }

            string? leftId = null;
            if (left != null)
            {
                Leave(connectionId);
                leftId = left.Id;
            }

            lock (room.Sync)
            {
                var now = Clock();
                var occupant = new Occupant
                {
                    ConnectionId = connectionId,
                    Player = player,
                    X = room.Definition.DoorX,
                    Y = room.Definition.DoorY
                };
                room.Occupants[connectionId] = occupant;
                _roomByConnection[connectionId] = room.Id;

                var snapshot = new RoomSnapshotDto(
                    room.Id,
                    room.Definition.Name,
                    room.Definition.Description,
                    room.Definition.Kind,
                    room.Definition.OwnerName,
                    room.Definition.Layout,
                    room.Definition.DoorX,
                    room.Definition.DoorY,
                    room.Definition.Furni.ToList(),
                    room.Occupants.Values.Select(o => room.ToDto(o, now)).ToList(),
                    room.Chat.Where(m => m.WhisperTo == null).ToList(),
                    room.Whiteboard,
                    room.QuietMode,
                    connectionId,
                    room.IsHost(player),
                    room.IsOwner(player),
                    room.Definition.MaxUsers,
                    room.IsOwner(player) ? room.Definition.Bans.ToList() : new List<RoomBan>());
                return (snapshot, room.ToDto(occupant, now), leftId);
            }
        }

        /// <summary>Removes the connection from its room. Returns the room id it left, if any.</summary>
        public string? Leave(string connectionId)
        {
            if (!_roomByConnection.TryRemove(connectionId, out var roomId) || !_rooms.TryGetValue(roomId, out var room))
            {
                return null;
            }
            lock (room.Sync)
            {
                room.Occupants.Remove(connectionId);
            }
            return roomId;
        }

        /// <summary>Other connections of the same user that are in any room (used to keep one avatar per account).</summary>
        public List<string> ConnectionsOf(Guid userId, string exceptConnectionId)
        {
            var result = new List<string>();
            foreach (var room in _rooms.Values)
            {
                lock (room.Sync)
                {
                    result.AddRange(room.Occupants.Values
                        .Where(o => o.Player.UserId == userId && o.ConnectionId != exceptConnectionId)
                        .Select(o => o.ConnectionId));
                }
            }
            return result;
        }

        // ---- moving and actions ----

        /// <summary>Starts walking toward a tile. Returns the path (first entry is where the walk starts) or null if there's no route.</summary>
        public (RoomRuntime Room, List<int[]> Path)? Move(string connectionId, int targetX, int targetY)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                if (!room.Occupants.TryGetValue(connectionId, out var occupant))
                {
                    return null;
                }
                var now = Clock();
                var start = occupant.PositionAt(now);
                var path = Pathfinder.FindPath(room.Walkable, start, (targetX, targetY));
                if (path.Count == 0)
                {
                    return null;
                }
                // Finish the step in progress first: the new walk starts when that tile is reached.
                // Starting it now would skip part of a step on every click, so spam-clicking made you faster.
                var startAt = occupant.CurrentStepEndsAt(now);
                occupant.X = start.X;
                occupant.Y = start.Y;
                occupant.Path = path;
                occupant.PathStartedAt = startAt;
                occupant.SittingOnFloor = false;
                occupant.Dance = 0;

                var wire = new List<int[]> { new[] { start.X, start.Y } };
                wire.AddRange(path.Select(p => new[] { p.X, p.Y }));
                return (room, wire);
            }
        }

        public (RoomRuntime Room, OccupantDto Occupant) SetDance(string connectionId, int dance)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                occupant.Dance = Math.Clamp(dance, 0, MaxDance);
                if (occupant.Dance > 0)
                {
                    occupant.SittingOnFloor = false;
                }
                return (room, room.ToDto(occupant, Clock()));
            }
        }

        /// <summary>Sits on the floor (or stands up). Can't sit while walking.</summary>
        public (RoomRuntime Room, OccupantDto Occupant) SetSitting(string connectionId, bool sitting)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                var now = Clock();
                var position = occupant.PositionAt(now);
                if (sitting && position != occupant.Destination)
                {
                    throw new WorldException("Stop walking first.");
                }
                occupant.X = position.X;
                occupant.Y = position.Y;
                occupant.Path = new();
                occupant.SittingOnFloor = sitting && !room.Seats.ContainsKey(position);
                if (sitting)
                {
                    occupant.Dance = 0;
                }
                return (room, room.ToDto(occupant, now));
            }
        }

        public RoomRuntime CheckEmote(string connectionId, string emoji)
        {
            if (!IsEmote(emoji))
            {
                throw new WorldException("Unknown emote.");
            }
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                if (occupant.Muted)
                {
                    throw new WorldException("A host has muted you in this room.");
                }
                ThrottleChat(occupant);
            }
            return room;
        }

        // ---- chat ----

        private void ThrottleChat(Occupant occupant)
        {
            var now = Clock();
            while (occupant.RecentChat.Count > 0 && now - occupant.RecentChat.Peek() > ChatBurstWindow)
            {
                occupant.RecentChat.Dequeue();
            }
            if (occupant.RecentChat.Count >= ChatBurstLimit)
            {
                throw new WorldException("Slow down! Wait a few seconds before chatting again.");
            }
            occupant.RecentChat.Enqueue(now);
        }

        private static void CheckCanTalk(RoomRuntime room, Occupant occupant)
        {
            if (occupant.Muted)
            {
                throw new WorldException("A host has muted you in this room.");
            }
            if (room.QuietMode && !room.IsHost(occupant.Player))
            {
                throw new WorldException("Quiet mode is on. Raise your hand to ask the teacher.");
            }
        }

        public (RoomRuntime Room, ChatMessageDto Message) Say(string connectionId, string text)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                CheckCanTalk(room, occupant);
                var cleaned = ChatFilter.Clean(text);
                if (cleaned.Text.Length == 0)
                {
                    throw new WorldException("Message is empty.");
                }
                ThrottleChat(occupant);

                var message = new ChatMessageDto(connectionId, occupant.Player.Name, cleaned.Text, Clock());
                room.AddChat(message);
                return (room, message);
            }
        }

        /// <summary>
        /// A whisper is seen by the sender, the target, and the room's hosts (so teachers and owners can
        /// keep chat safe). Returns the connections that should receive it.
        /// </summary>
        public (ChatMessageDto Message, List<string> Recipients) Whisper(string connectionId, string targetId, string text)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                CheckCanTalk(room, occupant);
                if (!room.Occupants.TryGetValue(targetId, out var target))
                {
                    throw new WorldException("That person isn't in this room anymore.");
                }
                if (target.ConnectionId == connectionId)
                {
                    throw new WorldException("You can't whisper to yourself.");
                }
                var cleaned = ChatFilter.Clean(text);
                if (cleaned.Text.Length == 0)
                {
                    throw new WorldException("Message is empty.");
                }
                ThrottleChat(occupant);

                var message = new ChatMessageDto(connectionId, occupant.Player.Name, cleaned.Text, Clock(),
                    WhisperTo: target.Player.Name);
                // Kept in history so reports include whispers, but never sent to late joiners.
                room.AddChat(message);
                var recipients = room.Occupants.Values
                    .Where(o => o.ConnectionId == connectionId || o.ConnectionId == targetId || room.IsHost(o.Player))
                    .Select(o => o.ConnectionId)
                    .Distinct()
                    .ToList();
                return (message, recipients);
            }
        }

        public (RoomRuntime Room, OccupantDto Occupant) RaiseHand(string connectionId, bool raised)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                occupant.HandRaised = raised;
                return (room, room.ToDto(occupant, Clock()));
            }
        }

        public (RoomRuntime Room, OccupantDto Occupant) UpdateLook(string connectionId, AvatarLook look)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                occupant.Player = occupant.Player with { Look = look };
                return (room, room.ToDto(occupant, Clock()));
            }
        }

        // ---- building ----

        /// <summary>Places a furni in the owner's current room. The caller takes it from the inventory first.</summary>
        public async Task<(RoomRuntime Room, FurniItem Item)> PlaceFurniAsync(string connectionId, string type, int x, int y, string dir)
        {
            var room = RequireOwner(connectionId);
            if (!Catalog.IsFurniType(type))
            {
                throw new WorldException("You can't place that.");
            }
            FurniItem item;
            lock (room.Sync)
            {
                if (room.Definition.Furni.Count >= MaxFurniPerRoom)
                {
                    throw new WorldException($"A room can hold up to {MaxFurniPerRoom} items.");
                }
                if (!room.IsFloor(x, y))
                {
                    throw new WorldException("Place it on the floor.");
                }
                if (x == room.Definition.DoorX && y == room.Definition.DoorY)
                {
                    throw new WorldException("Keep the door clear.");
                }
                if (room.Definition.Furni.Any(f => f.X == x && f.Y == y && f.Type != "rug") && type != "rug" ||
                    room.Definition.Furni.Any(f => f.X == x && f.Y == y && f.Type == "rug") && type == "rug")
                {
                    throw new WorldException("Something is already there.");
                }
                var now = Clock();
                if (RoomTemplates.IsBlocking(type) &&
                    room.Occupants.Values.Any(o => o.PositionAt(now) == (x, y) || o.Destination == (x, y)))
                {
                    throw new WorldException("Someone is standing there.");
                }
                item = new FurniItem { Id = RoomRuntime.NewFurniId(), Type = type, X = x, Y = y, Dir = NormalizeDir(dir) };
                room.Definition.Furni.Add(item);
                room.RebuildGrid();
            }
            await _store.SaveRoomAsync(room.Definition);
            return (room, item);
        }

        private static string NormalizeDir(string? dir) => dir is "ne" or "nw" or "se" or "sw" ? dir : "se";

        public async Task<(RoomRuntime Room, FurniItem Item)> RotateFurniAsync(string connectionId, string furniId)
        {
            var room = RequireOwner(connectionId);
            FurniItem item;
            lock (room.Sync)
            {
                item = room.Definition.Furni.FirstOrDefault(f => f.Id == furniId)
                       ?? throw new WorldException("That item is gone.");
                item.Dir = item.Dir switch { "se" => "sw", "sw" => "nw", "nw" => "ne", _ => "se" };
            }
            await _store.SaveRoomAsync(room.Definition);
            return (room, item);
        }

        /// <summary>Removes a furni from the owner's room; the caller returns it to the inventory.</summary>
        public async Task<(RoomRuntime Room, FurniItem Item)> PickUpFurniAsync(string connectionId, string furniId)
        {
            var room = RequireOwner(connectionId);
            FurniItem item;
            lock (room.Sync)
            {
                item = room.Definition.Furni.FirstOrDefault(f => f.Id == furniId)
                       ?? throw new WorldException("That item is gone.");
                if (item.Type == "whiteboard")
                {
                    throw new WorldException("The whiteboard is part of the classroom.");
                }
                room.Definition.Furni.Remove(item);
                room.RebuildGrid();
            }
            await _store.SaveRoomAsync(room.Definition);
            return (room, item);
        }

        // ---- host tools ----

        /// <summary>Throws unless the caller hosts their current room.</summary>
        public RoomRuntime RequireHost(string connectionId)
        {
            var room = CurrentRoom(connectionId);
            lock (room.Sync)
            {
                if (!room.Occupants.TryGetValue(connectionId, out var me) || !room.IsHost(me.Player))
                {
                    throw new WorldException("Only the room's host can do that.");
                }
            }
            return room;
        }

        public OccupantDto SetMuted(string hostConnectionId, string targetConnectionId, bool muted)
        {
            var room = RequireHost(hostConnectionId);
            lock (room.Sync)
            {
                var target = FindTarget(room, targetConnectionId);
                target.Muted = muted;
                return room.ToDto(target, Clock());
            }
        }

        /// <summary>Removes someone from the room; with <paramref name="ban"/>, the owner also bans them.</summary>
        public async Task<(RoomRuntime Room, Occupant Target)> KickAsync(string hostConnectionId, string targetConnectionId, bool ban)
        {
            var room = ban ? RequireOwner(hostConnectionId) : RequireHost(hostConnectionId);
            Occupant target;
            lock (room.Sync)
            {
                target = FindTarget(room, targetConnectionId);
                room.Occupants.Remove(target.ConnectionId);
                if (ban && room.Definition.Bans.All(b => b.UserId != target.Player.UserId))
                {
                    room.Definition.Bans.Add(new RoomBan { UserId = target.Player.UserId, Name = target.Player.Name });
                }
            }
            _roomByConnection.TryRemove(target.ConnectionId, out _);
            if (ban)
            {
                await _store.SaveRoomAsync(room.Definition);
            }
            return (room, target);
        }

        public async Task<RoomRuntime> UnbanAsync(string connectionId, Guid userId)
        {
            var room = RequireOwner(connectionId);
            lock (room.Sync)
            {
                room.Definition.Bans.RemoveAll(b => b.UserId == userId);
            }
            await _store.SaveRoomAsync(room.Definition);
            return room;
        }

        private static Occupant FindTarget(RoomRuntime room, string targetConnectionId)
        {
            if (!room.Occupants.TryGetValue(targetConnectionId, out var target))
            {
                throw new WorldException("That person isn't in this room anymore.");
            }
            if (room.IsHost(target.Player))
            {
                throw new WorldException("You can't do that to another host.");
            }
            return target;
        }

        public (RoomRuntime Room, string Text) SetWhiteboard(string hostConnectionId, string text)
        {
            var room = RequireHost(hostConnectionId);
            var cleaned = (text ?? string.Empty).Replace("\r", string.Empty);
            if (cleaned.Length > 2000)
            {
                cleaned = cleaned[..2000];
            }
            lock (room.Sync)
            {
                room.Whiteboard = cleaned;
            }
            return (room, cleaned);
        }

        public RoomRuntime SetQuietMode(string hostConnectionId, bool quiet)
        {
            var room = RequireHost(hostConnectionId);
            lock (room.Sync)
            {
                room.QuietMode = quiet;
            }
            return room;
        }

        public RoomRuntime ClearChat(string hostConnectionId)
        {
            var room = RequireHost(hostConnectionId);
            lock (room.Sync)
            {
                room.Chat.Clear();
            }
            return room;
        }

        public async Task ReportAsync(string reporterConnectionId, string targetConnectionId, string reason)
        {
            var room = CurrentRoom(reporterConnectionId);
            ChatReport report;
            lock (room.Sync)
            {
                if (!room.Occupants.TryGetValue(reporterConnectionId, out var reporter) ||
                    !room.Occupants.TryGetValue(targetConnectionId, out var target))
                {
                    throw new WorldException("That person isn't in this room anymore.");
                }
                var trimmed = (reason ?? string.Empty).Trim();
                report = new ChatReport
                {
                    ReporterId = reporter.Player.UserId,
                    ReporterName = reporter.Player.Name,
                    TargetUserId = target.Player.UserId,
                    TargetName = target.Player.Name,
                    RoomId = room.Id,
                    Reason = trimmed.Length > 300 ? trimmed[..300] : trimmed,
                    RecentChat = room.Chat.TakeLast(20).ToList()
                };
            }
            await _store.SaveReportAsync(report);
        }
    }
}
