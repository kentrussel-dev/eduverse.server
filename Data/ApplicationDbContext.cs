using AspNetCore.Identity.MongoDbCore.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace EduVerse.Server.Data
{
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