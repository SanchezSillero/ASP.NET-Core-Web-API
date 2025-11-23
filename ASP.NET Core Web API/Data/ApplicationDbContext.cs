using ASP.NET_Core_Web_API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace ASP.NET_Core_Web_API.Data
{
    public class ApplicationDbContext :IdentityDbContext<IdentityUser>
    {
       
            public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
                : base(options)
            {
            }

        public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();

    }
}
