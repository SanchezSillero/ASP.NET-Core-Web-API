namespace ASP.NET_Core_Web_API.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }

        public string Token { get; set; } = null!;

        public string UserId { get; set; } = null!;
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
        public DateTime CreatedAt { get; set; }

        public string CreatedByIp { get; set; } = null!;
        public string UserAgent { get; set; } = null!;
        public string DeviceName { get; set; } = null!;
        public string? DeviceId { get; set; }

        // rotation support
        public string? ReplacedByToken { get; set; } 
        public DateTime? RevokedAt { get; set; }
        public string? RevokedByIp { get; set; }
        public string? RevokedReason { get; set; }
    }
}
