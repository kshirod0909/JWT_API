using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using JWT_API.Modals;
using JWT_API.Repository;
using JWT_API.Security;
using Microsoft.AspNetCore.Authorization;
using System.Security.Cryptography;
using System.Text;

namespace JWT_API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthRepository _repo;
        private readonly JwtService _jwt;
        private readonly IConfiguration _config;

        public AuthController(AuthRepository repo, JwtService jwt, IConfiguration config)
        {
            _repo = repo;
            _jwt = jwt;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var existing = await _repo.GetUserByEmailAsync(request.Email);
            if (existing != null)
                return Conflict(new { Message = "Email already exists" });

            var (hash, salt) = PasswordHasher.HashPassword(request.Password);
            await _repo.CreateUserAsync(Guid.NewGuid(), request.Email, hash, salt, request.Role ?? "User");
            return Ok(new { Message = "User registered successfully" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _repo.GetUserByEmailAsync(request.Email);
            if (user == null)
                return Unauthorized("Invalid credentials");

            Guid userId = user.Id;
            if ((bool)user.IsLocked && user.LockoutEndUtc != null && user.LockoutEndUtc > DateTime.UtcNow)
                return Unauthorized($"Account locked until {user.LockoutEndUtc}");

            bool valid = PasswordHasher.Verify(request.Password, (byte[])user.PasswordHash, (byte[])user.PasswordSalt);
            if (!valid)
            {
                await _repo.IncrementFailedAttemptAsync(userId);
                int max = int.Parse(_config["Lockout:MaxFailedAttempts"]);
                int failed = (int)user.FailedLoginCount + 1;
                if (failed >= max)
                {
                    int mins = int.Parse(_config["Lockout:LockoutMinutes"]);
                    await _repo.LockUserAsync(userId, DateTime.UtcNow.AddMinutes(mins));
                    return Unauthorized($"Account locked for {mins} minutes");
                }
                return Unauthorized("Invalid credentials");
            }

            await _repo.ResetFailedAttemptsAsync(userId);
            var accessToken = _jwt.GenerateAccessToken(userId, user.Email, user.Role);

            var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
            using var sha = SHA256.Create();
            var refreshHash = sha.ComputeHash(Encoding.UTF8.GetBytes(refreshToken));
            var expiresAt = DateTime.UtcNow.AddDays(int.Parse(_config["Jwt:RefreshTokenExpirationDays"]));
            await _repo.SaveRefreshTokenAsync(userId, refreshHash, expiresAt);

            return Ok(new AuthResponse
            {
                Success = true,
                Message = "Login successful",
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }

        [Authorize]
        [HttpGet("protected")]
        public IActionResult Protected()
        {
            return Ok(new { Message = "You are authorized" });
        }
    }
}
