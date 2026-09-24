using System.Collections.Concurrent;
using MongoDB.Driver;

namespace EduVerse.Server.Realtime
{
    /// <summary>Saves user-created rooms and moderation reports.</summary>
    public interface IRoomStore
    {
        Task<List<RoomDefinition>> LoadRoomsAsync();
        Task SaveRoomAsync(RoomDefinition room);
        Task DeleteRoomAsync(string roomId);
        Task SaveReportAsync(ChatReport report);
    }

    public class MongoRoomStore : IRoomStore
    {
        private readonly IMongoCollection<RoomDefinition> _rooms;
        private readonly IMongoCollection<ChatReport> _reports;

        public MongoRoomStore(IConfiguration configuration)
        {
            var client = new MongoClient(configuration.GetConnectionString("MongoDB"));
            var database = client.GetDatabase(configuration["MongoDB:DatabaseName"] ?? "EduVerse");
            _rooms = database.GetCollection<RoomDefinition>("Rooms");
            _reports = database.GetCollection<ChatReport>("ChatReports");
        }

        public Task<List<RoomDefinition>> LoadRoomsAsync() => _rooms.Find(_ => true).ToListAsync();

        public Task SaveRoomAsync(RoomDefinition room) =>
            _rooms.ReplaceOneAsync(r => r.Id == room.Id, room, new ReplaceOptions { IsUpsert = true });

        public Task DeleteRoomAsync(string roomId) => _rooms.DeleteOneAsync(r => r.Id == roomId);

        public Task SaveReportAsync(ChatReport report) => _reports.InsertOneAsync(report);
    }

    /// <summary>Keeps everything in memory. Used when no MongoDB is configured (local testing).</summary>
    public class InMemoryRoomStore : IRoomStore
    {
        private readonly ConcurrentDictionary<string, RoomDefinition> _rooms = new();
        public ConcurrentBag<ChatReport> Reports { get; } = new();

        public Task<List<RoomDefinition>> LoadRoomsAsync() => Task.FromResult(_rooms.Values.ToList());

        public Task SaveRoomAsync(RoomDefinition room)
        {
            _rooms[room.Id] = room;
            return Task.CompletedTask;
        }

        public Task DeleteRoomAsync(string roomId)
        {
            _rooms.TryRemove(roomId, out _);
            return Task.CompletedTask;
        }

        public Task SaveReportAsync(ChatReport report)
        {
            Reports.Add(report);
            return Task.CompletedTask;
        }
    }
}
