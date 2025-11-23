using ASP.NET_Core_Web_API.Models;

namespace ASP.NET_Core_Web_API.Services
{
    public interface ITokenSvc
    {
        string CreateAccessToken(ApplicationUser user, IEnumerable<string> roles, IDictionary<string, string>? extraClaims = null);
        Task<RefreshToken> CreateRefreshTokenAsync(ApplicationUser user, string ip, string userAgent, string deviceName, string? deviceId);
        Task<bool> RevokeRefreshTokenAsync(string token);
        Task<RefreshToken?> GetRefreshTokenAsync(string protectedToken);
    }
}
