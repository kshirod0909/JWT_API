namespace JWT_API.Modals
{
    public class RefreshRequest
    {
        public string RefreshToken { get; set; }
    }

    public class RefreshToken
    {
        public Guid Id { get; set; }
        public Guid UserId { get; set; }
        public byte[] TokenHash { get; set; }
        public DateTime ExpiresAtUtc { get; set; }
        public string Email { get; set; }
    }
}
