namespace ASP.NET_Core_Web_API.Models.Auth
{
    public class LoginDto
    {
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        // Opcionales: para vincular el refresh token al dispositivo
        public string? DeviceName { get; set; }
        public string? DeviceId { get; set; }
    }
}
