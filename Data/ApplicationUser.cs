using AspNetCore.Identity.MongoDbCore.Models;
using MongoDbGenericRepository.Attributes;
using MongoDB.Bson.Serialization.Attributes;

namespace EduVerse.Server.Data
{
    [CollectionName("Users")]
    [BsonIgnoreExtraElements]
    public class ApplicationUser : MongoIdentityUser<Guid>
    {
        private string fullName = string.Empty;
        private string avatar = "default.png";
        private bool isTeacher;
        private readonly DateTime createdAt;
        private AccountType accountType = AccountType.Email;
        private string authProvider = "Email";

        public string FullName
        {
            get => fullName;
            set => fullName = value ?? string.Empty;
        }

        public string Avatar
        {
            get => avatar;
            set => avatar = value ?? "default.png";
        }

        public bool IsTeacher
        {
            get => isTeacher;
            set => isTeacher = value;
        }

        public DateTime CreatedAt => createdAt;

        public AccountType AccountType
        {
            get => accountType;
            set => accountType = value;
        }

        public string AuthProvider
        {
            get => authProvider;
            set => authProvider = value ?? "Email";
        }

        public ApplicationUser() : base()
        {
            Id = Guid.NewGuid();
            SecurityStamp = Guid.NewGuid().ToString();
            createdAt = DateTime.UtcNow;
        }

        public static ApplicationUser CreateEmailUser(string email, string fullName, bool isTeacher = false)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("Email cannot be null or empty", nameof(email));

            return new ApplicationUser
            {
                UserName = email,
                Email = email,
                FullName = string.IsNullOrEmpty(fullName) ? email : fullName,
                IsTeacher = isTeacher,
                EmailConfirmed = false, // Requires confirmation
                AuthProvider = "Email",
                AccountType = AccountType.Email
            };
        }

        public static ApplicationUser CreateGoogleUser(string email, string? fullName)
        {
            if (string.IsNullOrEmpty(email))
                throw new ArgumentException("Email cannot be null or empty", nameof(email));

            return new ApplicationUser
            {
                UserName = email,
                Email = email,
                FullName = string.IsNullOrEmpty(fullName) ? email : fullName,
                IsTeacher = false, // Default to student for Google sign-ins
                EmailConfirmed = true, // Google emails are pre-confirmed
                AuthProvider = "Google",
                AccountType = AccountType.Google
            };
        }
    }
}