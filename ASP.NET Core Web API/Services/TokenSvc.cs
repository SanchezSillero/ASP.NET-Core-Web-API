using ASP.NET_Core_Web_API.Data;
using ASP.NET_Core_Web_API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ASP.NET_Core_Web_API.Services;

public class TokenSvc : ITokenSvc
{
    private readonly IConfiguration _config;
    private readonly ApplicationDbContext _context;   

    public TokenSvc(IConfiguration config, ApplicationDbContext context)
    {
        _config = config;
        _context = context;       
    }

    // Helper: calculo SHA256 base64 (usado para persistir token hashed en DB)
    private static string HashToken(string token)
    {
        var bytes = Encoding.UTF8.GetBytes(token);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    public string CreateAccessToken(ApplicationUser user, IEnumerable<string> roles, IDictionary<string, string>? extraClaims = null)
    {
        var jwt = _config.GetSection("JwtSettings");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt["Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new Claim("uid", user.Id),
            new Claim("userSecret", user.UserJwtSecret ?? string.Empty)
        };

        // Roles
        foreach (var r in roles) claims.Add(new Claim(ClaimTypes.Role, r));

        if (extraClaims != null)
        {
            foreach (var kv in extraClaims) claims.Add(new Claim(kv.Key, kv.Value));
        }

        var token = new JwtSecurityToken(
            issuer: jwt["Issuer"],
            audience: jwt["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(jwt["AccessTokenExpirationMinutes"]!)),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // Crea refresh token: guarda HASH en DB y DEVUELVE el raw token (para poner en cookie HttpOnly)
    public async Task<RefreshToken> CreateRefreshTokenAsync(ApplicationUser user, string ip, string userAgent, string deviceName, string? deviceId)
    {
        var jwt = _config.GetSection("JwtSettings");
        int refreshDays = int.Parse(jwt["RefreshTokenExpirationDays"]!);

        // Raw token seguro
        var rawBytes = RandomNumberGenerator.GetBytes(64);
        var rawToken = Convert.ToBase64String(rawBytes);

        var hashed = HashToken(rawToken);

        var refresh = new RefreshToken
        {
            Token = hashed, // persistimos el hash
            UserId = user.Id,
            Expires = DateTime.UtcNow.AddDays(refreshDays),
            IsRevoked = false,
            CreatedByIp = ip,
            UserAgent = userAgent,
            DeviceName = deviceName,
            DeviceId = deviceId,
            CreatedAt = DateTime.UtcNow
        };

        // Limitar sesiones: leer config o fallback
        int maxSessions = _config.GetValue<int?>("Auth:MaxSessionsPerUser") ?? 5;

        var active = await _context.RefreshTokens
            .Where(r => r.UserId == user.Id && !r.IsRevoked && r.Expires > DateTime.UtcNow)
            .OrderBy(r => r.CreatedAt)
            .ToListAsync();

        if (active.Count >= maxSessions)
        {
            // revocar las más antiguas hasta dejar espacio
            int toRevoke = (active.Count - maxSessions) + 1;
            var oldest = active.Take(toRevoke).ToList();
            foreach (var o in oldest)
            {
                o.IsRevoked = true;
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

        // Devolver objeto con token en claro (cliente lo guarda en cookie HttpOnly). 
        return new RefreshToken
        {
            Token = rawToken,             // <-- raw para el cliente
            Expires = refresh.Expires,
            CreatedAt = refresh.CreatedAt,
            DeviceName = deviceName,
            DeviceId = deviceId,
            CreatedByIp = ip,
            UserAgent = userAgent,
            UserId = user.Id
        };
    }

    // Busca refresh token por raw token (cliente envía raw, nosotros hasheamos y comparamos)
    public async Task<RefreshToken?> GetRefreshTokenAsync(string rawToken)
    {
        var hashed = HashToken(rawToken);

        var stored = await _context.RefreshTokens
            .FirstOrDefaultAsync(r => r.Token == hashed && !r.IsRevoked && r.Expires > DateTime.UtcNow);

        if (stored == null) return null;

        // Devolver una copia con Token = rawToken para que el caller tenga el raw si lo necesita
        return new RefreshToken
        {
            Id = stored.Id,
            Token = rawToken, // raw
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

    // Revoca token a partir de rawToken
    public async Task<bool> RevokeRefreshTokenAsync(string rawToken)
    {
        var hashed = HashToken(rawToken);

        var stored = await _context.RefreshTokens.FirstOrDefaultAsync(r => r.Token == hashed);
        if (stored == null) return false;

        if (stored.IsRevoked) return true;

        stored.IsRevoked = true;
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

    public async Task<RefreshToken?> RotateRefreshTokenAsync(string rawToken)
    {
        var stored = await GetRefreshTokenAsync(rawToken);
        if (stored == null) return null;

        // Revocar token actual
        await RevokeRefreshTokenAsync(rawToken);

        // Crear token nuevo para el mismo dispositivo
        var user = await _context.Users.FindAsync(stored.UserId);

        return await CreateRefreshTokenAsync(
            user!,
            stored.CreatedByIp,
            stored.UserAgent,
            stored.DeviceName,
            stored.DeviceId
        );
    }

}
