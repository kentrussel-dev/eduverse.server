using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace EduVerse.Server.Realtime
{
    /// <summary>
    /// Real-time connection for the virtual world. Clients connect to /hubs/world with their JWT
    /// (as the access_token query parameter) and receive these events:
    /// userJoined, userLeft, userMoved, userUpdated, emote, wave, chat, whisper, whiteboard, roomSettings,
    /// roomUpdated, chatCleared, furniAdded, furniUpdated, furniRemoved, profile, kicked, notice.
    /// </summary>
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class WorldHub : Hub
    {
        private const string PlayerKey = "player";

        private readonly WorldState _world;
        private readonly ProfileService _profiles;
        private readonly ILogger<WorldHub> _logger;

        public WorldHub(WorldState world, ProfileService profiles, ILogger<WorldHub> logger)
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
            var profile = await _profiles.GetAsync(userId, user.FindFirstValue("gender"));
            Context.Items[PlayerKey] = new PlayerInfo(userId, name, isTeacher, profile.Look, user.FindFirstValue("isAdmin") == "True");
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

        private async Task SendProfileAsync(WorldProfile profile) =>
            await Clients.Caller.SendAsync("profile", _profiles.ToDto(Player, profile));

        // ---- profile, shop, inventory ----

        public async Task<ProfileDto> GetProfile() => _profiles.ToDto(Player, await _profiles.GetAsync(Player.UserId));

        public IReadOnlyList<CatalogItem> GetCatalog() => Catalog.Items;

        public Task<ProfileDto> Buy(string itemId) => Guard(async () =>
        {
            var profile = await _profiles.BuyAsync(Player.UserId, itemId, Player.IsAdmin);
            _logger.LogInformation("{UserId} bought {ItemId}", Player.UserId, itemId);
            return _profiles.ToDto(Player, profile);
        });

        public Task<ProfileDto> ClaimDailyBonus() => Guard(async () =>
            _profiles.ToDto(Player, await _profiles.ClaimDailyBonusAsync(Player.UserId)));

        public Task<ProfileDto> SetLook(AvatarLook look) => Guard(async () =>
        {
            var profile = await _profiles.SetLookAsync(Player.UserId, look);
            Context.Items[PlayerKey] = Player with { Look = profile.Look };
            if (_world.RoomOf(Context.ConnectionId) != null)
            {
                var (room, occupant) = _world.UpdateLook(Context.ConnectionId, profile.Look);
                await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
            }
            return _profiles.ToDto(Player, profile);
        });

        // ---- rooms ----

        public List<RoomSummaryDto> GetRooms(string? tab = "public", string? query = null) =>
            _world.ListRooms(Player.UserId, tab ?? "public", query);

        public Task<RoomSummaryDto> CreateRoom(CreateRoomRequest request) => Guard(async () =>
        {
            var room = await _world.CreateRoomAsync(Player, request);
            _logger.LogInformation("Room {RoomId} ({Kind}) created by {UserId}", room.Id, room.Kind, Player.UserId);
            return new RoomSummaryDto(room.Id, room.Name, room.Description, room.Kind, room.OwnerName, 0, room.MaxUsers, true);
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

        public Task<RoomInfoDto> UpdateRoomSettings(RoomSettingsRequest request) => Guard(async () =>
        {
            var room = await _world.UpdateSettingsAsync(Context.ConnectionId, request);
            var info = room.Info();
            await Clients.Group(Group(room.Id)).SendAsync("roomUpdated", new { info.Id, info.Name, info.Description, info.Kind, info.MaxUsers });
            return info;
        });

        public Task DeleteRoom() => Guard(async () =>
        {
            var (roomId, occupants, furni) = await _world.DeleteRoomAsync(Context.ConnectionId);
            foreach (var connection in occupants)
            {
                await Groups.RemoveFromGroupAsync(connection, Group(roomId));
                await Clients.Client(connection).SendAsync("kicked",
                    connection == Context.ConnectionId ? "Room deleted. Its furniture is back in your inventory." : "The owner deleted this room.");
            }
            await SendProfileAsync(await _profiles.GiveFurniAsync(Player.UserId, furni));
            _logger.LogInformation("Room {RoomId} deleted by {UserId}", roomId, Player.UserId);
        });

        // ---- moving and actions ----

        public Task Move(int x, int y) => Guard(async () =>
        {
            var result = _world.Move(Context.ConnectionId, x, y);
            if (result is { } moved)
            {
                await Clients.Group(Group(moved.Room.Id)).SendAsync("userMoved", Context.ConnectionId, moved.Path);
            }
        });

        public Task Dance(int style) => Guard(async () =>
        {
            var (room, occupant) = _world.SetDance(Context.ConnectionId, style);
            await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
        });

        public Task Sit(bool sitting) => Guard(async () =>
        {
            var (room, occupant) = _world.SetSitting(Context.ConnectionId, sitting);
            await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
        });

        public Task Wave() => Guard(async () =>
        {
            var room = _world.RoomOf(Context.ConnectionId) ?? throw new WorldException("You're not in a room.");
            await Clients.Group(Group(room.Id)).SendAsync("wave", Context.ConnectionId);
        });

        public Task Emote(string emoji) => Guard(async () =>
        {
            var room = _world.CheckEmote(Context.ConnectionId, emoji);
            await Clients.Group(Group(room.Id)).SendAsync("emote", Context.ConnectionId, emoji);
        });

        public Task Say(string text) => Guard(async () =>
        {
            var (room, message) = _world.Say(Context.ConnectionId, text);
            await Clients.Group(Group(room.Id)).SendAsync("chat", message);
        });

        public Task Whisper(string targetId, string text) => Guard(async () =>
        {
            var (message, recipients) = _world.Whisper(Context.ConnectionId, targetId, text);
            await Clients.Clients(recipients).SendAsync("whisper", message);
        });

        public Task RaiseHand(bool raised) => Guard(async () =>
        {
            var (room, occupant) = _world.RaiseHand(Context.ConnectionId, raised);
            await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
        });

        public Task Report(string targetId, string reason) => Guard(async () =>
        {
            await _world.ReportAsync(Context.ConnectionId, targetId, reason);
            _logger.LogWarning("Chat report filed by {UserId} against connection {Target}", Player.UserId, targetId);
            await Clients.Caller.SendAsync("notice", "Thanks. Your report was sent to the moderators.");
        });

        // ---- building (room owner) ----

        public Task PlaceFurni(string type, int x, int y, string dir) => Guard(async () =>
        {
            var profile = await _profiles.TakeFurniAsync(Player.UserId, type);
            try
            {
                var (room, item) = await _world.PlaceFurniAsync(Context.ConnectionId, type, x, y, dir);
                await Clients.Group(Group(room.Id)).SendAsync("furniAdded", item);
            }
            catch
            {
                profile = await _profiles.GiveFurniAsync(Player.UserId, new[] { type });
                throw;
            }
            finally
            {
                await SendProfileAsync(profile);
            }
        });

        public Task RotateFurni(string furniId) => Guard(async () =>
        {
            var (room, item) = await _world.RotateFurniAsync(Context.ConnectionId, furniId);
            await Clients.Group(Group(room.Id)).SendAsync("furniUpdated", item);
        });

        public Task PickUpFurni(string furniId) => Guard(async () =>
        {
            var (room, item) = await _world.PickUpFurniAsync(Context.ConnectionId, furniId);
            await Clients.Group(Group(room.Id)).SendAsync("furniRemoved", item.Id);
            await SendProfileAsync(await _profiles.GiveFurniAsync(Player.UserId, new[] { item.Type }));
        });

        // ---- host tools ----

        public Task Mute(string targetId, bool muted) => Guard(async () =>
        {
            var occupant = _world.SetMuted(Context.ConnectionId, targetId, muted);
            var room = _world.RoomOf(Context.ConnectionId)!;
            await Clients.Group(Group(room.Id)).SendAsync("userUpdated", occupant);
            await Clients.Client(targetId).SendAsync("notice", muted ? "A host muted you." : "You can chat again.");
        });

        public Task Kick(string targetId, bool ban = false) => Guard(async () =>
        {
            var (room, target) = await _world.KickAsync(Context.ConnectionId, targetId, ban);
            await Groups.RemoveFromGroupAsync(target.ConnectionId, Group(room.Id));
            await Clients.Group(Group(room.Id)).SendAsync("userLeft", target.ConnectionId);
            await Clients.Client(target.ConnectionId).SendAsync("kicked",
                ban ? $"You were banned from {room.Definition.Name}." : $"A host removed you from {room.Definition.Name}.");
            if (ban)
            {
                await Clients.Caller.SendAsync("roomSettings", new { bans = room.Info().Bans });
            }
        });

        public Task Unban(Guid userId) => Guard(async () =>
        {
            var room = await _world.UnbanAsync(Context.ConnectionId, userId);
            await Clients.Caller.SendAsync("roomSettings", new { bans = room.Info().Bans });
        });

        // ---- the drawing board ----

        public Task<BoardDto> GetBoard() => Guard(() =>
        {
            var room = _world.RoomOf(Context.ConnectionId) ?? throw new WorldException("You're not in a room.");
            lock (room.Sync)
            {
                return Task.FromResult(room.Board());
            }
        });

        public Task UpdateBoard(string scene, string preview) => Guard(async () =>
        {
            var room = _world.UpdateBoard(Context.ConnectionId, scene, preview);
            await Clients.OthersInGroup(Group(room.Id)).SendAsync("boardUpdated", scene ?? string.Empty, room.BoardPreview, Context.ConnectionId);
        });

        public Task ClearBoard() => Guard(async () =>
        {
            var room = _world.ClearBoard(Context.ConnectionId);
            await Clients.Group(Group(room.Id)).SendAsync("boardUpdated", string.Empty, string.Empty, Context.ConnectionId);
        });

        public Task SetBoardAccess(bool everyone) => Guard(async () =>
        {
            var room = _world.SetBoardAccess(Context.ConnectionId, everyone);
            await SendBoardAccessAsync(room);
        });

        public Task AllowBoardDrawer(string occupantId, bool allowed) => Guard(async () =>
        {
            var room = _world.AllowBoardDrawer(Context.ConnectionId, occupantId, allowed);
            await SendBoardAccessAsync(room);
        });

        private async Task SendBoardAccessAsync(RoomRuntime room)
        {
            BoardDto board;
            lock (room.Sync)
            {
                board = room.Board();
            }
            await Clients.Group(Group(room.Id)).SendAsync("boardAccess", new { board.Everyone, board.Drawers });
        }

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
