using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using MongoDbGenericRepository.Attributes;

namespace EduVerse.Server.Data
{
    [CollectionName("Users")]
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        private string _fullName = string.Empty;
        private string _avatar = "default.png";

        public string FullName
        {
            get => _fullName;
            set => _fullName = value ?? throw new ArgumentNullException(nameof(value));
        }

        public string Avatar
        {
            get => _avatar;
            set => _avatar = value ?? throw new ArgumentNullException(nameof(value));
        }

        public bool IsTeacher { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }

    public class ApplicationDbContext
    {
        public static void ConfigureIdentity(IServiceCollection services, IConfiguration configuration)
        {
            services.AddIdentityCore<ApplicationUser>(options => { })
                .AddRoles<MongoIdentityRole<Guid>>()
                .AddMongoDbStores<ApplicationUser, MongoIdentityRole<Guid>, Guid>(
                    configuration.GetConnectionString("MongoDB"),
                    configuration["MongoDB:DatabaseName"]
                )
                .AddDefaultTokenProviders()
                .AddSignInManager();
        }
    }
}