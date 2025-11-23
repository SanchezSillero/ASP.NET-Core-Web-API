using ASP.NET_Core_Web_API.Data;
using ASP.NET_Core_Web_API.Models;
using ASP.NET_Core_Web_API.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// ------------------------
// PostgreSQL
// ------------------------
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// ------------------------
// Identity
// ------------------------
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// ------------------------
// JWT CONFIG 
// ------------------------
var jwt = builder.Configuration.GetSection("JwtSettings");
var keyValue = jwt["Key"] ?? throw new InvalidOperationException("JwtSettings:Key is missing");
var key = Encoding.UTF8.GetBytes(keyValue);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = true;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),

        ValidateIssuer = true,
        ValidIssuer = jwt.GetValue<string>("Issuer"),

        ValidateAudience = true,
        ValidAudience = jwt.GetValue<string>("Audience"),

        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };

    options.Events = new JwtBearerEvents();
});

// ------------------------
// Servicios propios
// ------------------------
builder.Services.AddScoped<ITokenSvc, TokenSvc>();

// ------------------------
// Controllers + Swagger
// ------------------------
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// ------------------------
// Pipeline
// ------------------------
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();   //Debe ir ANTES de UseAuthorization
app.UseAuthorization();

app.MapControllers();

app.Run();