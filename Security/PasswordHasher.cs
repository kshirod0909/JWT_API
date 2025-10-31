using System;
using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace JWT_API.Security
{
    public static class PasswordHasher
    {
        // Returns (hash, salt)
        public static (byte[] Hash, byte[] Salt) HashPassword(string password)
        {
            // Generate salt
            var salt = new byte[16];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = 2, // number of threads
                Iterations = 3, // time cost
                MemorySize = 65536 // 64 MB
            };

            var hash = argon.GetBytes(32); // 32 bytes output
            return (hash, salt);
        }

        public static bool Verify(string password, byte[] storedHash, byte[] storedSalt)
        {
            var argon = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = storedSalt,
                DegreeOfParallelism = 2,
                Iterations = 3,
                MemorySize = 65536
            };

            var computed = argon.GetBytes(32);
            return CryptographicOperations.FixedTimeEquals(computed, storedHash);
        }
    }
}
