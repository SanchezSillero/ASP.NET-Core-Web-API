using ASP.NET_Core_Web_API.Models;

namespace ASP.NET_Core_Web_API.Services
{
    public interface ITokenSvc
    {
        string CreateAccessToken(ApplicationUser user, IEnumerable<string> roles, IDictionary<string, string>? extraClaims = null);

        Task<RefreshToken> CreateRefreshTokenAsync(ApplicationUser user, string ip, string userAgent, string deviceName, string? deviceId);

        Task<RefreshToken?> GetRefreshTokenAsync(string rawToken);

        Task<bool> RevokeRefreshTokenAsync(string rawToken);

        Task<RefreshToken?> RotateRefreshTokenAsync(string rawToken);

        Task<TokenPair> GenerateTokensAsync(ApplicationUser user, IEnumerable<string> roles, HttpResponse response, string ip, string userAgent, string deviceName, string? deviceId);

        void SetRefreshTokenCookie(HttpResponse response, string rawToken, DateTime expires);

        Task<IEnumerable<RefreshTokenInfo>> GetActiveSessionsAsync(string userId);

        Task RevokeAllRefreshTokensAsync(string userId);
        Task<bool> RevokeRefreshTokenByIdAsync(int id);
    }
}
