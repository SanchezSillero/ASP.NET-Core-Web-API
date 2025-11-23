namespace ASP.NET_Core_Web_API.Models
{
    public class AuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; } = null!;
        public string Action { get; set; } = null!; // "Login","Register","Refresh","Revoke", etc.
        public string? Details { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string? Ip { get; set; }
    }
}
