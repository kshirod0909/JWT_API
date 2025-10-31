using System;
using System.Data;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.SqlClient;

namespace JWT_API.Repository
{
    public class AuthRepository
    {
        private readonly string _connectionString;
        public AuthRepository(IConfiguration config)
        {
            _connectionString = config.GetConnectionString("Default");
        }

        private IDbConnection Connection => new SqlConnection(_connectionString);

        public async Task<dynamic> GetUserByEmailAsync(string email)
        {
            using var conn = Connection;
            return await conn.QueryFirstOrDefaultAsync("SELECT * FROM Users WHERE Email=@Email", new { Email = email });
        }

        public async Task CreateUserAsync(Guid id, string email, byte[] passwordHash, byte[] passwordSalt, string role)
        {
            using var conn = Connection;
            await conn.ExecuteAsync("INSERT INTO Users(Id,Email,PasswordHash,PasswordSalt,Role) VALUES(@Id,@Email,@Hash,@Salt,@Role)",
                new { Id = id, Email = email, Hash = passwordHash, Salt = passwordSalt, Role = role });
        }

        public async Task IncrementFailedAttemptAsync(Guid userId)
        {
            using var conn = Connection;
            await conn.ExecuteAsync("UPDATE Users SET FailedLoginCount=FailedLoginCount+1 WHERE Id=@Id", new { Id = userId });
        }

        public async Task ResetFailedAttemptsAsync(Guid userId)
        {
            using var conn = Connection;
            await conn.ExecuteAsync("UPDATE Users SET FailedLoginCount=0, LockoutEndUtc=NULL WHERE Id=@Id", new { Id = userId });
        }

        public async Task LockUserAsync(Guid userId, DateTime lockUntil)
        {
            using var conn = Connection;
            await conn.ExecuteAsync("UPDATE Users SET IsLocked=1, LockoutEndUtc=@LockoutEndUtc WHERE Id=@Id",
                new { Id = userId, LockoutEndUtc = lockUntil });
        }

        public async Task SaveRefreshTokenAsync(Guid userId, byte[] tokenHash, DateTime expiresAt)
        {
            using var conn = Connection;
            await conn.ExecuteAsync("INSERT INTO RefreshTokens(UserId,TokenHash,ExpiresAtUtc) VALUES(@UserId,@TokenHash,@ExpiresAtUtc)",
                new { UserId = userId, TokenHash = tokenHash, ExpiresAtUtc = expiresAt });
        }
    }
}
