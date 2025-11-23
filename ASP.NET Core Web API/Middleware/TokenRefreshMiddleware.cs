using ASP.NET_Core_Web_API.Models;
using ASP.NET_Core_Web_API.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

public class TokenRefreshMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _config;
    private readonly ITokenSvc _tokenSvc;
    private readonly UserManager<ApplicationUser> _userManager;

    // threshold in seconds before token expiry to attempt refresh
    private readonly TimeSpan _refreshThreshold = TimeSpan.FromMinutes(2);

    public TokenRefreshMiddleware(RequestDelegate next, IConfiguration config, ITokenSvc tokenSvc, UserManager<ApplicationUser> userManager)
    {
        _next = next;
        _config = config;
        _tokenSvc = tokenSvc;
        _userManager = userManager;
    }

    public async Task Invoke(HttpContext context)
    {
        try
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
            {
                var tokenString = authHeader.Substring("Bearer ".Length).Trim();
                var handler = new JwtSecurityTokenHandler();
                JwtSecurityToken? jwtToken = null;

                try
                {
                    jwtToken = handler.ReadJwtToken(tokenString);
                }
                catch
                {
                    jwtToken = null;
                }

                if (jwtToken != null)
                {
                    // get exp
                    var expClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp);
                    if (expClaim != null && long.TryParse(expClaim.Value, out var expVal))
                    {
                        var exp = DateTimeOffset.FromUnixTimeSeconds(expVal).UtcDateTime;
                        var timeLeft = exp - DateTime.UtcNow;

                        // if token expiring soon or already expired, try refresh
                        if (timeLeft <= _refreshThreshold)
                        {
                            // read refresh token cookie
                            if (context.Request.Cookies.TryGetValue("refreshToken", out var refreshRaw))
                            {
                                // Try to rotate and issue new tokens
                                var newRefresh = await _tokenSvc.RotateRefreshTokenAsync(refreshRaw);
                                if (newRefresh != null)
                                {
                                    // find user
                                    var stored = await _tokenSvc.GetRefreshTokenAsync(newRefresh.Token);
                                    if (stored == null) { await _next(context); return; }

                                    var user = await _userManager.FindByIdAsync(stored.UserId);
                                    if (user != null)
                                    {
                                        var roles = await _userManager.GetRolesAsync(user);
                                        var newAccess = _tokenSvc.CreateAccessToken(user, roles);
                                        // set new refresh cookie
                                        _tokenSvc.SetRefreshTokenCookie(context.Response, newRefresh.Token, newRefresh.Expires);
                                        // expose new access token in header (frontend should read it and update client storage)
                                        context.Response.Headers["X-New-Access-Token"] = newAccess;
                                        // optionally: also add it to a response cookie or body if desired
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // swallow — don't block request on refresh failure
        }

        await _next(context);
    }
}
