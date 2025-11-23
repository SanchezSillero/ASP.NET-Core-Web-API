namespace ASP.NET_Core_Web_API.Models
{
    public class RefreshToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = null!;
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
        public string UserId { get; set; } = null!;

        // Metadata

        public required string CreatedByIp { get; set; }
        public required string UserAgent { get; set; }
        public required string DeviceName { get; set; }
        public string? DeviceId { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}
