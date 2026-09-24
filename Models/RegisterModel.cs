namespace EduVerse.Server.Models
{
    public class RegisterModel
    {
        public string Email { get; set; }
        public string FullName { get; set; }
        public string Password { get; set; }
        public bool IsTeacher { get; set; }
        /// <summary>"boy" or "girl"; picks the first random look.</summary>
        public string? Gender { get; set; }
    }
}

