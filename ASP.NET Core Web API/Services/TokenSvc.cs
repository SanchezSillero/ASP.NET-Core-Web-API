using ASP.NET_Core_Web_API.Data;
using ASP.NET_Core_Web_API.Models;
using ASP.NET_Core_Web_API.Models.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ASP.NET_Core_Web_API.Services;

public class TokenSvc
{
    private readonly IConfiguration _config;
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;

    public TokenSvc(IConfiguration config, ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        _config = config;
        _context = context;
        _userManager = userManager;
    }

    public async Task<TokenResponse> GenerateTokensAsync(IdentityUser user)
    {
        var jwtSettings = _config.GetSection("JwtSettings");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!)
        };

        // Crear Access Token
        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSettings["AccessTokenExpirationMinutes"]!)),
            signingCredentials: creds
        );

        string accessToken = new JwtSecurityTokenHandler().WriteToken(token);

        // Crear Refresh Token
        string refreshToken = Guid.NewGuid().ToString();

        var refreshEntity = new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            Expires = DateTime.UtcNow.AddDays(int.Parse(jwtSettings["RefreshTokenExpirationDays"]!)),
            IsRevoked = false
        };

        _context.RefreshTokens.Add(refreshEntity);
        await _context.SaveChangesAsync();

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    public async Task<IdentityUser?> GetUserFromRefreshTokenAsync(string refreshToken)
    {
        var stored = await _context.RefreshTokens.FirstOrDefaultAsync(r => r.Token == refreshToken);

        if (stored == null || stored.IsRevoked || stored.Expires < DateTime.UtcNow)
            return null;

        return await _userManager.FindByIdAsync(stored.UserId);
    }

    public async Task RevokeRefreshTokenAsync(string refreshToken)
    {
        var stored = await _context.RefreshTokens.FirstOrDefaultAsync(r => r.Token == refreshToken);
        if (stored != null)
        {
            stored.IsRevoked = true;
            await _context.SaveChangesAsync();
        }
    }
}
