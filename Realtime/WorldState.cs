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
    }

    /// <summary>The live state of one room.</summary>
    public class RoomRuntime
    {
        public const int ChatHistorySize = 50;

        public RoomRuntime(RoomDefinition definition)
        {
            Definition = definition;
            var depth = definition.Layout.Count;
            var width = definition.Layout.Max(row => row.Length);
            Walkable = new bool[width, depth];
            for (var y = 0; y < depth; y++)
            {
                for (var x = 0; x < definition.Layout[y].Length; x++)
                {
                    Walkable[x, y] = definition.Layout[y][x] != 'x';
                }
            }
            foreach (var item in definition.Furni)
            {
                if (item.X >= width || item.Y >= depth)
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

        public object Sync { get; } = new();
        public RoomDefinition Definition { get; }
        public bool[,] Walkable { get; }
        public Dictionary<(int X, int Y), FurniItem> Seats { get; } = new();
        public Dictionary<string, Occupant> Occupants { get; } = new();
        public LinkedList<ChatMessageDto> Chat { get; } = new();
        public string Whiteboard { get; set; } = string.Empty;
        public bool QuietMode { get; set; }

        public string Id => Definition.Id;

        /// <summary>Hosts can moderate: the room's owner, or any teacher in a built-in classroom.</summary>
        public bool IsHost(PlayerInfo player) =>
            Definition.OwnerId == player.UserId ||
            (Definition.BuiltIn && Definition.Kind == RoomKind.Classroom && player.IsTeacher);

        public OccupantDto ToDto(Occupant o, DateTime now)
        {
            var (x, y) = o.PositionAt(now);
            return new OccupantDto(o.ConnectionId, o.Player.UserId.ToString(), o.Player.Name, o.Player.IsTeacher,
                IsHost(o.Player), o.Player.Look, x, y, o.Muted, o.HandRaised);
        }

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
        private const int ChatBurstLimit = 5;
        private static readonly TimeSpan ChatBurstWindow = TimeSpan.FromSeconds(6);

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

        /// <summary>Rooms shown in the navigator. Classrooms and private rooms are only listed to their owner; others join by code.</summary>
        public List<RoomSummaryDto> ListRooms(Guid userId)
        {
            return _rooms.Values
                .Where(r => r.Definition.BuiltIn || r.Definition.Kind is RoomKind.Public or RoomKind.Study ||
                            r.Definition.OwnerId == userId)
                .Select(Summarize)
                .OrderBy(r => r.Kind)
                .ThenByDescending(r => r.UserCount)
                .ThenBy(r => r.Name)
                .ToList();
        }

        public List<RoomSummaryDto> ListOwnedRooms(Guid userId) =>
            _rooms.Values.Where(r => r.Definition.OwnerId == userId).Select(Summarize).ToList();

        private static RoomSummaryDto Summarize(RoomRuntime r)
        {
            int count;
            lock (r.Sync)
            {
                count = r.Occupants.Count;
            }
            return new RoomSummaryDto(r.Id, r.Definition.Name, r.Definition.Description, r.Definition.Kind,
                r.Definition.OwnerName, count, r.Definition.MaxUsers);
        }

        public async Task<RoomDefinition> CreateRoomAsync(PlayerInfo owner, CreateRoomRequest request)
        {
            var name = ChatFilter.Clean(request.Name);
            if (name.Text.Length < 3 || name.Text.Length > 40)
            {
                throw new WorldException("Room names need 3 to 40 characters.");
            }
            if (name.WasFiltered)
            {
                throw new WorldException("Please choose a different room name.");
            }
            if (request.Kind == RoomKind.Lobby)
            {
                throw new WorldException("That room type can't be created.");
            }
            if (request.Kind == RoomKind.Classroom && !owner.IsTeacher)
            {
                throw new WorldException("Only teachers can create classrooms.");
            }
            if (ListOwnedRooms(owner.UserId).Count >= MaxRoomsPerOwner)
            {
                throw new WorldException($"You can own up to {MaxRoomsPerOwner} rooms.");
            }

            var template = RoomTemplates.Names.Contains(request.Template)
                ? request.Template
                : request.Kind == RoomKind.Classroom ? "classroom" : "empty";
            var room = RoomTemplates.Create(template);
            room.Id = NewRoomCode();
            room.Name = name.Text;
            room.Description = ChatFilter.Clean(request.Description).Text;
            if (room.Description.Length > 120)
            {
                room.Description = room.Description[..120];
            }
            room.Kind = request.Kind;
            room.OwnerId = owner.UserId;
            room.OwnerName = owner.Name;
            room.CreatedAt = DateTime.UtcNow;

            await _store.SaveRoomAsync(room);
            _rooms[room.Id] = new RoomRuntime(room);
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
                if (room.Occupants.Count >= room.Definition.MaxUsers)
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
                    room.Definition.Furni,
                    room.Occupants.Values.Select(o => room.ToDto(o, now)).ToList(),
                    room.Chat.ToList(),
                    room.Whiteboard,
                    room.QuietMode,
                    connectionId,
                    room.IsHost(player));
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

        /// <summary>Starts walking toward a tile. Returns the path (first entry is where the walk starts) or null if there's no route.</summary>
        public (RoomRuntime Room, List<int[]> Path)? Move(string connectionId, int targetX, int targetY)
        {
            var room = RoomOf(connectionId) ?? throw new WorldException("You're not in a room.");
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
                occupant.X = start.X;
                occupant.Y = start.Y;
                occupant.Path = path;
                occupant.PathStartedAt = now;

                var wire = new List<int[]> { new[] { start.X, start.Y } };
                wire.AddRange(path.Select(p => new[] { p.X, p.Y }));
                return (room, wire);
            }
        }

        public (RoomRuntime Room, ChatMessageDto Message) Say(string connectionId, string text)
        {
            var room = RoomOf(connectionId) ?? throw new WorldException("You're not in a room.");
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                if (occupant.Muted)
                {
                    throw new WorldException("A host has muted you in this room.");
                }
                if (room.QuietMode && !room.IsHost(occupant.Player))
                {
                    throw new WorldException("Quiet mode is on. Raise your hand to ask the teacher.");
                }

                var now = Clock();
                while (occupant.RecentChat.Count > 0 && now - occupant.RecentChat.Peek() > ChatBurstWindow)
                {
                    occupant.RecentChat.Dequeue();
                }
                if (occupant.RecentChat.Count >= ChatBurstLimit)
                {
                    throw new WorldException("Slow down! Wait a few seconds before chatting again.");
                }

                var cleaned = ChatFilter.Clean(text);
                if (cleaned.Text.Length == 0)
                {
                    throw new WorldException("Message is empty.");
                }
                occupant.RecentChat.Enqueue(now);

                var message = new ChatMessageDto(connectionId, occupant.Player.Name, cleaned.Text, now);
                room.AddChat(message);
                return (room, message);
            }
        }

        public (RoomRuntime Room, OccupantDto Occupant) RaiseHand(string connectionId, bool raised)
        {
            var room = RoomOf(connectionId) ?? throw new WorldException("You're not in a room.");
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                occupant.HandRaised = raised;
                return (room, room.ToDto(occupant, Clock()));
            }
        }

        public (RoomRuntime Room, OccupantDto Occupant) UpdateLook(string connectionId, AvatarLook look)
        {
            var room = RoomOf(connectionId) ?? throw new WorldException("You're not in a room.");
            lock (room.Sync)
            {
                var occupant = room.Occupants[connectionId];
                occupant.Player = occupant.Player with { Look = look };
                return (room, room.ToDto(occupant, Clock()));
            }
        }

        /// <summary>Runs a host-only action. Throws unless the caller hosts their current room.</summary>
        public RoomRuntime RequireHost(string connectionId)
        {
            var room = RoomOf(connectionId) ?? throw new WorldException("You're not in a room.");
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

        public (RoomRuntime Room, Occupant Target) GetKickTarget(string hostConnectionId, string targetConnectionId)
        {
            var room = RequireHost(hostConnectionId);
            lock (room.Sync)
            {
                return (room, FindTarget(room, targetConnectionId));
            }
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
            var room = RoomOf(reporterConnectionId) ?? throw new WorldException("You're not in a room.");
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
