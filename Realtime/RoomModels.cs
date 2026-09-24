using MongoDB.Bson.Serialization.Attributes;

namespace EduVerse.Server.Realtime
{
    public enum RoomKind
    {
        Lobby = 0,
        Public = 1,
        Classroom = 2,
        Study = 3,
        Private = 4
    }

    /// <summary>A piece of furniture placed on a room tile.</summary>
    public class FurniItem
    {
        public string Type { get; set; } = string.Empty;
        public int X { get; set; }
        public int Y { get; set; }

        /// <summary>Screen facing: "ne", "nw", "se" or "sw".</summary>
        public string Dir { get; set; } = "se";
    }

    /// <summary>The saved definition of a room. Live state (who is inside) lives in <see cref="RoomRuntime"/>.</summary>
    [BsonIgnoreExtraElements]
    public class RoomDefinition
    {
        [BsonId]
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public RoomKind Kind { get; set; }
        public Guid? OwnerId { get; set; }
        public string OwnerName { get; set; } = string.Empty;

        /// <summary>Rows of tiles top to bottom: '0' is floor, 'x' is empty space.</summary>
        public List<string> Layout { get; set; } = new();
        public int DoorX { get; set; }
        public int DoorY { get; set; }
        public List<FurniItem> Furni { get; set; } = new();
        public int MaxUsers { get; set; } = 30;
        public bool BuiltIn { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class ChatReport
    {
        [BsonId]
        public Guid Id { get; set; } = Guid.NewGuid();
        public Guid ReporterId { get; set; }
        public string ReporterName { get; set; } = string.Empty;
        public Guid TargetUserId { get; set; }
        public string TargetName { get; set; } = string.Empty;
        public string RoomId { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
        public List<ChatMessageDto> RecentChat { get; set; } = new();
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    // ---- DTOs sent to clients ----

    public record AvatarLook(string Skin, string Hair, string Shirt, string Pants)
    {
        public static readonly AvatarLook Default = new("#f1c27d", "#4a3021", "#3f7fd9", "#2d3a4a");
    }

    public record OccupantDto(
        string Id,
        string UserId,
        string Name,
        bool IsTeacher,
        bool IsHost,
        AvatarLook Look,
        int X,
        int Y,
        bool Muted,
        bool HandRaised);

    public record ChatMessageDto(string FromId, string Name, string Text, DateTime SentAt, bool System = false);

    public record RoomSummaryDto(
        string Id,
        string Name,
        string Description,
        RoomKind Kind,
        string OwnerName,
        int UserCount,
        int MaxUsers);

    public record RoomSnapshotDto(
        string Id,
        string Name,
        string Description,
        RoomKind Kind,
        string OwnerName,
        List<string> Layout,
        int DoorX,
        int DoorY,
        List<FurniItem> Furni,
        List<OccupantDto> Occupants,
        List<ChatMessageDto> Chat,
        string Whiteboard,
        bool QuietMode,
        string YouId,
        bool YouAreHost);

    public record CreateRoomRequest(string Name, string Description, RoomKind Kind, string Template);
}
