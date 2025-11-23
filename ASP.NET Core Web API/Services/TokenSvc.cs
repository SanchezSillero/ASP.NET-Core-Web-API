using ASP.NET_Core_Web_API.Data;
using ASP.NET_Core_Web_API.Models;
using ASP.NET_Core_Web_API.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

public class TokenSvc : ITokenSvc
{
    private readonly IConfiguration _config;
    private readonly ApplicationDbContext _context;

    // nombre cookie configurable
    private const string RefreshCookieName = "refreshToken";

    public TokenSvc(IConfiguration config, ApplicationDbContext context)
    {
        _config = config;
        _context = context;
    }

    private static string HashToken(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    public string CreateAccessToken(ApplicationUser user, IEnumerable<string> roles, IDictionary<string, string>? extraClaims = null)
    {
        var jwt = _config.GetSection("JwtSettings");
        var keyValue = jwt["Key"] ?? throw new InvalidOperationException("JwtSettings:Key missing");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyValue));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim("uid", user.Id),
            new Claim("userSecret", user.UserJwtSecret ?? string.Empty)
        };

        foreach (var r in roles) claims.Add(new Claim(ClaimTypes.Role, r));
        if (extraClaims != null)
            foreach (var kv in extraClaims) claims.Add(new Claim(kv.Key, kv.Value));

        var token = new JwtSecurityToken(
            issuer: jwt["Issuer"],
            audience: jwt["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(jwt["AccessTokenExpirationMinutes"]!)),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // Core: crea refresh token (hash en DB) y devuelve raw token
    public async Task<RefreshToken> CreateRefreshTokenAsync(ApplicationUser user, string ip, string userAgent, string deviceName, string? deviceId)
    {
        var jwt = _config.GetSection("JwtSettings");
        int refreshDays = int.Parse(jwt["RefreshTokenExpirationDays"]!);

        var rawBytes = RandomNumberGenerator.GetBytes(64);
        var rawToken = Convert.ToBase64String(rawBytes);
        var hashed = HashToken(rawToken);

        var refresh = new RefreshToken
        {
            Token = hashed,
            UserId = user.Id,
            Expires = DateTime.UtcNow.AddDays(refreshDays),
            IsRevoked = false,
            CreatedByIp = ip,
            UserAgent = userAgent,
            DeviceName = deviceName,
            DeviceId = deviceId,
            CreatedAt = DateTime.UtcNow
        };

        int maxSessions = _config.GetValue<int?>("Auth:MaxSessionsPerUser") ?? 5;

        var active = await _context.RefreshTokens
            .Where(r => r.UserId == user.Id && !r.IsRevoked && r.Expires > DateTime.UtcNow)
            .OrderBy(r => r.CreatedAt)
            .ToListAsync();

        if (active.Count >= maxSessions)
        {
            int toRevoke = (active.Count - maxSessions) + 1;
            foreach (var o in active.Take(toRevoke))
            {
                o.IsRevoked = true;
                o.RevokedAt = DateTime.UtcNow;
                o.RevokedReason = "AUTO_REVOKE_OLDEST_SESSION";
                _context.AuditLogs.Add(new AuditLog
                {
                    UserId = o.UserId,
                    Action = "AUTO_REVOKE_OLDEST_SESSION",
                    Ip = o.CreatedByIp,
                    Details = $"Revoked device {o.DeviceName}"
                });
            }
        }

        _context.RefreshTokens.Add(refresh);
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = user.Id,
            Action = "CREATE_REFRESH_TOKEN",
            Ip = ip,
            Details = $"Device: {deviceName}; Agent: {userAgent}"
        });

        await _context.SaveChangesAsync();

        return new RefreshToken
        {
            Token = rawToken, // raw for client
            Expires = refresh.Expires,
            CreatedAt = refresh.CreatedAt,
            DeviceName = deviceName,
            DeviceId = deviceId,
            CreatedByIp = ip,
            UserAgent = userAgent,
            UserId = user.Id
        };
    }

    public async Task<RefreshToken?> GetRefreshTokenAsync(string rawToken)
    {
        var hashed = HashToken(rawToken);

        var stored = await _context.RefreshTokens
            .FirstOrDefaultAsync(r => r.Token == hashed && !r.IsRevoked && r.Expires > DateTime.UtcNow);

        if (stored == null) return null;

        return new RefreshToken
        {
            Id = stored.Id,
            Token = rawToken,
            Expires = stored.Expires,
            IsRevoked = stored.IsRevoked,
            UserId = stored.UserId,
            CreatedAt = stored.CreatedAt,
            CreatedByIp = stored.CreatedByIp,
            DeviceName = stored.DeviceName,
            DeviceId = stored.DeviceId,
            UserAgent = stored.UserAgent
        };
    }

    public async Task<bool> RevokeRefreshTokenAsync(string rawToken)
    {
        var hashed = HashToken(rawToken);
        var stored = await _context.RefreshTokens.FirstOrDefaultAsync(r => r.Token == hashed);
        if (stored == null) return false;
        if (stored.IsRevoked) return true;

        stored.IsRevoked = true;
        stored.RevokedAt = DateTime.UtcNow;
        stored.RevokedReason = "REVOKED_BY_USER";
        _context.AuditLogs.Add(new AuditLog
        {
            UserId = stored.UserId,
            Action = "REVOKE_REFRESH_TOKEN",
            Ip = stored.CreatedByIp,
            Details = $"Device: {stored.DeviceName}"
        });

        await _context.SaveChangesAsync();
        return true;
    }

    // Rotación: revoca el token recibido y crea uno nuevo para el mismo device
    public async Task<RefreshToken?> RotateRefreshTokenAsync(string rawToken)
    {
        var stored = await _context.RefreshTokens
            .FirstOrDefaultAsync(r => r.Token == HashToken(rawToken) && !r.IsRevoked && r.Expires > DateTime.UtcNow);

        if (stored == null) return null;

        // Mark revoked (rotate)
        stored.IsRevoked = true;
        stored.RevokedAt = DateTime.UtcNow;
        stored.RevokedReason = "ROTATED";
        // Create new refresh token for same user/device
        var user = await _context.Users.OfType<ApplicationUser>().FirstOrDefaultAsync(u => u.Id == stored.UserId);
        if (user == null) return null;

        // create new refresh token
        var newRefresh = await CreateRefreshTokenAsync(user, stored.CreatedByIp, stored.UserAgent, stored.DeviceName, stored.DeviceId);

        // link replaced tokens (store hashed value)
        stored.ReplacedByToken = HashToken(newRefresh.Token);
        await _context.SaveChangesAsync();

        return newRefresh;
    }

    // -----------------------------
    // NUEVO: Genera access + refresh y pone cookie HttpOnly
    // -----------------------------
    public async Task<TokenPair> GenerateTokensAsync(ApplicationUser user, IEnumerable<string> roles, HttpResponse response, string ip, string userAgent, string deviceName, string? deviceId)
    {
        // access
        var access = CreateAccessToken(user, roles);

        // refresh (raw token)
        var refresh = await CreateRefreshTokenAsync(user, ip, userAgent, deviceName, deviceId);

        // set cookie
        SetRefreshTokenCookie(response, refresh.Token, refresh.Expires);

        return new TokenPair
        {
            AccessToken = access,
            RefreshToken = refresh.Token
        };
    }

    // helper to set cookie
    public void SetRefreshTokenCookie(HttpResponse response, string rawToken, DateTime expires)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = expires,
            Path = "/"
        };
        response.Cookies.Append(RefreshCookieName, rawToken, cookieOptions);
    }

    // get active sessions for user
    public async Task<IEnumerable<RefreshTokenInfo>> GetActiveSessionsAsync(string userId)
    {
        var tokens = await _context.RefreshTokens
            .Where(r => r.UserId == userId && !r.IsRevoked && r.Expires > DateTime.UtcNow)
            .OrderByDescending(r => r.CreatedAt)
            .ToListAsync();

        return tokens.Select(t => new RefreshTokenInfo
        {
            Id = t.Id,
            DeviceName = t.DeviceName,
            DeviceId = t.DeviceId,
            CreatedAt = t.CreatedAt,
            Expires = t.Expires,
            UserAgent = t.UserAgent,
            CreatedByIp = t.CreatedByIp
        });
    }

    // revoke all sessions for a user
    public async Task RevokeAllRefreshTokensAsync(string userId)
    {
        var tokens = await _context.RefreshTokens
            .Where(r => r.UserId == userId && !r.IsRevoked)
            .ToListAsync();

        foreach (var t in tokens)
        {
            t.IsRevoked = true;
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedReason = "REVOKE_ALL";
        }

        _context.AuditLogs.Add(new AuditLog
        {
            UserId = userId,
            Action = "REVOKE_ALL_SESSIONS",
            Ip = "system",
            Details = "Revoked all sessions for user"
        });

        await _context.SaveChangesAsync();
    }

    //revocar por usuario
    public async Task<bool> RevokeRefreshTokenByIdAsync(int id)
    {
        var token = await _context.RefreshTokens.FirstOrDefaultAsync(r => r.Id == id);
        if (token == null) return false;

        token.IsRevoked = true;
        token.RevokedAt = DateTime.UtcNow;
        token.RevokedReason = "REVOKED_MANUALLY";

        await _context.SaveChangesAsync();
        return true;
    }
}

// helper TokenSvc
public class TokenPair
{
    public string AccessToken { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
}

public class RefreshTokenInfo
{
    public int Id { get; set; }
    public string DeviceName { get; set; } = string.Empty;
    public string? DeviceId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime Expires { get; set; }
    public string UserAgent { get; set; } = string.Empty;
    public string CreatedByIp { get; set; } = string.Empty;
}