using ASP.NET_Core_Web_API.Models;
using ASP.NET_Core_Web_API.Models.Auth;
using ASP.NET_Core_Web_API.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASP.NET_Core_Web_API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly TokenSvc _tokenService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        TokenSvc tokenService)
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
            UserJwtSecret = Guid.NewGuid().ToString() // recomendado (invalida tokens antiguos)
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

        // Create access token
        var accessToken = _tokenService.CreateAccessToken(user, roles);

        // Create refresh token
        var refreshToken = await _tokenService.CreateRefreshTokenAsync(
            user,
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            Request.Headers["User-Agent"].ToString() ?? "unknown",
            deviceName: dto.DeviceName ?? "Unknown",
            deviceId: dto.DeviceId
        );

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken.Token
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

        var accessToken = _tokenService.CreateAccessToken(user, roles);

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefresh!.Token
        };
    }

    // -------------------------
    // LOGOUT
    // -------------------------
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(RefreshRequest dto)
    {
        await _tokenService.RevokeRefreshTokenAsync(dto.RefreshToken);
        return Ok("Logged out");
    }

    [HttpGet("protected")]
    [Microsoft.AspNetCore.Authorization.Authorize]
    public IActionResult ProtectedTest()
    {
        return Ok("You are authenticated!");
    }
}
