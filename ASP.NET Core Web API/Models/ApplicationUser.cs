using Microsoft.AspNetCore.Identity;

namespace ASP.NET_Core_Web_API.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? UserJwtSecret { get; set; } //Secret por usuario, para invalidar tokens individualmente
    }
}
