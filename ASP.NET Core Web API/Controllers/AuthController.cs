using ASP.NET_Core_Web_API.Models;
using ASP.NET_Core_Web_API.Models.Auth;
using ASP.NET_Core_Web_API.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASP.NET_Core_Web_API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ITokenSvc _tokenService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ITokenSvc tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
    }

    // -------------------------
    // REGISTER
    // -------------------------
    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var user = new ApplicationUser
        {
            Email = dto.Email,
            UserName = dto.Email,
            UserJwtSecret = Guid.NewGuid().ToString()
        };

        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok("User created");
    }

    // -------------------------
    // LOGIN
    // -------------------------
    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return Unauthorized("Invalid credentials");

        var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
        if (!result.Succeeded) return Unauthorized("Invalid credentials");

        var roles = await _userManager.GetRolesAsync(user);

        // Issue tokens and set refresh cookie
        var pair = await _tokenService.GenerateTokensAsync(
            user,
            roles,
            Response,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            Request.Headers["User-Agent"].ToString(),
            dto.DeviceName ?? "Unknown",
            dto.DeviceId
        );

        return new TokenResponse
        {
            AccessToken = pair.AccessToken,
            RefreshToken = pair.RefreshToken
        };
    }

    // -------------------------
    // REFRESH
    // -------------------------
    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(RefreshRequest dto)
    {
        var stored = await _tokenService.GetRefreshTokenAsync(dto.RefreshToken);
        if (stored == null) return Unauthorized("Invalid refresh token");

        var user = await _userManager.FindByIdAsync(stored.UserId);
        if (user == null) return Unauthorized("Invalid refresh token");

        var roles = await _userManager.GetRolesAsync(user);

        // Rotate refresh token
        var newRefresh = await _tokenService.RotateRefreshTokenAsync(dto.RefreshToken);
        if (newRefresh == null) return Unauthorized("Invalid refresh");

        // Set cookie
        _tokenService.SetRefreshTokenCookie(Response, newRefresh.Token, newRefresh.Expires);

        var accessToken = _tokenService.CreateAccessToken(user, roles);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefresh.Token
        };
    }

    // -------------------------
    // LOGOUT
    // -------------------------
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(RefreshRequest dto)
    {
        await _tokenService.RevokeRefreshTokenAsync(dto.RefreshToken);
        Response.Cookies.Delete("refreshToken");
        return Ok("Logged out");
    }

    [HttpGet("protected")]
    [Microsoft.AspNetCore.Authorization.Authorize]
    public IActionResult ProtectedTest()
    {
        return Ok("You are authenticated!");
    }



    // -------------------------
    // 
    // -------------------------
    [HttpGet("sessions")]
    [Authorize]
    public async Task<IActionResult> GetSessions()
    {
        var userId = User.FindFirst("uid")?.Value;
        if (userId == null) return Unauthorized();

        var sessions = await _tokenService.GetActiveSessionsAsync(userId);

        return Ok(sessions);
    }


    // -------------------------
    // Revocar sesion concreta
    // -------------------------
    [HttpPost("sessions/revoke/{id:int}")]
    [Authorize]
    public async Task<IActionResult> RevokeSession(int id)
    {
        var userId = User.FindFirst("uid")?.Value;
        if (userId == null) return Unauthorized();

        var tokens = await _tokenService.GetActiveSessionsAsync(userId);
        var target = tokens.FirstOrDefault(t => t.Id == id);

        if (target == null)
            return NotFound("Session not found");

        // Necesitamos raw token → entonces hacemos un método específico
        var success = await _tokenService.RevokeRefreshTokenByIdAsync(id);
        if (!success) return BadRequest("Could not revoke session");

        return Ok("Session revoked");
    }

    // -------------------------
    // Revocar todas las sesiones
    // -------------------------
    [HttpPost("sessions/revoke-all")]
    [Authorize]
    public async Task<IActionResult> RevokeAllSessions()
    {
        var userId = User.FindFirst("uid")?.Value;
        if (userId == null) return Unauthorized();

        await _tokenService.RevokeAllRefreshTokensAsync(userId);

        return Ok("All sessions revoked");
    }


}
