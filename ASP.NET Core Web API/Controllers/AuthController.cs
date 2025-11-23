using ASP.NET_Core_Web_API.Models.Auth;
using ASP.NET_Core_Web_API.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ASP.NET_Core_Web_API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly TokenSvc _tokenService;

    public AuthController(
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager,
        TokenSvc tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto dto)
    {
        var user = new IdentityUser { Email = dto.Email, UserName = dto.Email };
        var result = await _userManager.CreateAsync(user, dto.Password);

        if (!result.Succeeded)
            return BadRequest(result.Errors);

        return Ok("User created");
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login(LoginDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return Unauthorized("Invalid credentials");

        var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
        if (!result.Succeeded) return Unauthorized("Invalid credentials");

        return await _tokenService.GenerateTokensAsync(user);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh(RefreshRequest dto)
    {
        var user = await _tokenService.GetUserFromRefreshTokenAsync(dto.RefreshToken);
        if (user == null) return Unauthorized("Invalid refresh token");

        await _tokenService.RevokeRefreshTokenAsync(dto.RefreshToken);

        return await _tokenService.GenerateTokensAsync(user);
    }

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
