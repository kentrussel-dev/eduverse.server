using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace EduVerse.Server.Realtime
{
    /// <summary>
    /// Real-time connection for the virtual world. Clients connect to /hubs/world with their JWT
    /// (as the access_token query parameter) and receive these events:
    /// userJoined, userLeft, userMoved, userUpdated, chat, whiteboard, roomSettings, chatCleared, kicked, notice.
    /// </summary>
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class WorldHub : Hub
    {
        private const string PlayerKey = "player";

        private readonly WorldState _world;
        private readonly IUserProfiles _profiles;
        private readonly ILogger<WorldHub> _logger;

        public WorldHub(WorldState world, IUserProfiles profiles, ILogger<WorldHub> logger)
        {
            _world = world;
            _profiles = profiles;
            _logger = logger;
        }

        private static string Group(string roomId) => "room:" + roomId;

        public override async Task OnConnectedAsync()
        {
            await _world.EnsureLoadedAsync();
            var user = Context.User ?? throw new HubException("Not signed in.");
            if (!Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
            {
                throw new HubException("Invalid sign-in token.");
            }
            var isTeacher = bool.TryParse(user.FindFirstValue("isTeacher"), out var teacher) && teacher;
            var name = DisplayName(user.FindFirstValue(ClaimTypes.Name), user.FindFirstValue(ClaimTypes.Email));
            var look = await _profiles.GetLookAsync(userId);
            Context.Items[PlayerKey] = new PlayerInfo(userId, name, isTeacher, look);
            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            var roomId = _world.Leave(Context.ConnectionId);
            if (roomId != null)
            {
                await Clients.Group(Group(roomId)).SendAsync("userLeft", Context.ConnectionId);
            }
            await base.OnDisconnectedAsync(exception);
        }

        private PlayerInfo Player => (PlayerInfo)Context.Items[PlayerKey]!;

        /// <summary>
        /// Shows only a first name and last initial ("Juan D.") so students' full names aren't public.
        /// </summary>
        public static string DisplayName(string? fullName, string? email)
        {
            var parts = (fullName ?? string.Empty).Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0 || parts[0].Contains('@'))
            {
                var local = (email ?? "Student").Split('@')[0];
                return local.Length > 12 ? local[..12] : local;
            }
            var first = parts[0].Length > 16 ? parts[0][..16] : parts[0];
            return parts.Length > 1 ? $"{first} {char.ToUpperInvariant(parts[^1][0])}." : first;
        }

        private static async Task<T> Guard<T>(Func<Task<T>> action)
        {
            try
            {
                return await action();
            }
            catch (WorldException ex)
            {
                throw new HubException(ex.Message);
            }
        }

        private static async Task Guard(Func<Task> action)
        {
            try
            {
                await action();
            }
            catch (WorldException ex)
            {
                throw new HubException(ex.Message);
            }
        }

        public object GetProfile() => new
        {
            userId = Player.UserId,
            name = Player.Name,
            isTeacher = Player.IsTeacher,
            look = Player.Look
        };

        public List<RoomSummaryDto> GetRooms() => _world.ListRooms(Player.UserId);

        public Task<RoomSummaryDto> CreateRoom(CreateRoomRequest request) => Guard(async () =>
        {
            var room = await _world.CreateRoomAsync(Player, request);
            _logger.LogInformation("Room {RoomId} ({Kind}) created by {UserId}", room.Id, room.Kind, Player.UserId);
            return new RoomSummaryDto(room.Id, room.Name, room.Description, room.Kind, room.OwnerName, 0, room.MaxUsers);
        });

        public Task<RoomSnapshotDto> JoinRoom(string roomId) => Guard(async () =>
        {
            // One avatar per account: joining here removes any other window's avatar.
            foreach (var other in _world.ConnectionsOf(Player.UserId, Context.ConnectionId))
            {
                var otherRoom = _world.Leave(other);
                if (otherRoom != null)
                {
                    await Groups.RemoveFromGroupAsync(other, Group(otherRoom));
                    await Clients.Group(Group(otherRoom)).SendAsync("userLeft", other);
                }
                await Clients.Client(other).SendAsync("kicked", "You joined a room from another window.");
            }

            var (snapshot, you, leftRoomId) = _world.Join(Context.ConnectionId, Player, roomId);
            if (leftRoomId != null)
            {
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, Group(leftRoomId));
                await Clients.Group(Group(leftRoomId)).SendAsync("userLeft", Context.ConnectionId);
            }
            await Clients.Group(Group(snapshot.Id)).SendAsync("userJoined", you);
            await Groups.AddToGroupAsync(Context.ConnectionId, Group(snapshot.Id));
            return snapshot;
        });

        public async Task LeaveRoom()
        {
            var roomId = _world.Leave(Context.ConnectionId);
            if (roomId != null)
            {
                await Groups.RemoveFromGroupAsync(Context.ConnectionId, Group(roomId));
                await Clients.Group(Group(roomId)).SendAsync("userLeft", Context.ConnectionId);
            }
        }

        public Task Move(int x, int y) => Guard(async () =>
        {
            var result = _world.Move(Context.ConnectionId, x, y);
            if (result is { } moved)
            {
                await Clients.Group(Group(moved.Room.Id)).SendAsync("userMoved", Context.ConnectionId, moved.Path);
            }
        });

        public Task Say(string text) => Guard(async () =>
        {
            var (room, message) = _world.Say(Context.ConnectionId, text);
            await Clients.Group(Group(room.Id)).SendAsync("chat", message);
        });

        public Task RaiseHand(bool raised) => Guard(async () =>
        {
            var (room, occupant) = _world.RaiseHand(Context.ConnectionId, raised);
            await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
        });

        public Task SetLook(AvatarLook look) => Guard(async () =>
        {
            if (!AvatarLooks.IsValid(look))
            {
                throw new WorldException("Invalid avatar colors.");
            }
            Context.Items[PlayerKey] = Player with { Look = look };
            await _profiles.SaveLookAsync(Player.UserId, look);
            if (_world.RoomOf(Context.ConnectionId) != null)
            {
                var (room, occupant) = _world.UpdateLook(Context.ConnectionId, look);
                await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
            }
        });

        public Task Report(string targetId, string reason) => Guard(async () =>
        {
            await _world.ReportAsync(Context.ConnectionId, targetId, reason);
            _logger.LogWarning("Chat report filed by {UserId} against connection {Target}", Player.UserId, targetId);
            await Clients.Caller.SendAsync("notice", "Thanks. Your report was sent to the moderators.");
        });

        // ---- Host (teacher / room owner) tools ----

        public Task Mute(string targetId, bool muted) => Guard(async () =>
        {
            var occupant = _world.SetMuted(Context.ConnectionId, targetId, muted);
            var room = _world.RoomOf(Context.ConnectionId)!;
            await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
            await Clients.Client(targetId).SendAsync("notice", muted ? "A host muted you." : "You can chat again.");
        });

        public Task Kick(string targetId) => Guard(async () =>
        {
            var (room, target) = _world.GetKickTarget(Context.ConnectionId, targetId);
            _world.Leave(target.ConnectionId);
            await Groups.RemoveFromGroupAsync(target.ConnectionId, Group(room.Id));
            await Clients.Group(Group(room.Id)).SendAsync("userLeft", target.ConnectionId);
            await Clients.Client(target.ConnectionId).SendAsync("kicked", $"A host removed you from {room.Definition.Name}.");
        });

        public Task SetWhiteboard(string text) => Guard(async () =>
        {
            var (room, cleaned) = _world.SetWhiteboard(Context.ConnectionId, text);
            await Clients.Group(Group(room.Id)).SendAsync("whiteboard", cleaned);
        });

        public Task SetQuietMode(bool quiet) => Guard(async () =>
        {
            var room = _world.SetQuietMode(Context.ConnectionId, quiet);
            await Clients.Group(Group(room.Id)).SendAsync("roomSettings", new { quietMode = quiet });
        });

        public Task ClearChat() => Guard(async () =>
        {
            var room = _world.ClearChat(Context.ConnectionId);
            await Clients.Group(Group(room.Id)).SendAsync("chatCleared");
        });
    }
}
