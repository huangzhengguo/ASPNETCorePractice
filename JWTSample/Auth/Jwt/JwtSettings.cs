using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;

namespace JWTSample.Jwt;

public class JwtSettings
{
    public string Issuer { get; }
    public string Audience { get; }
    public byte[] Key { get; set; }

    public JwtSettings(byte[] key, string issuer, string audience)
    {
        Key = key;
        Issuer = issuer;
        Audience = audience;
    }

    public TokenValidationParameters ValidationParameters {
        get 
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,

                ValidIssuer = Issuer,
                ValidAudience = Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Key)
            };
        }
    }

    public static JwtSettings FromConfiguration(IConfiguration configuration)
    {
        var issuer = configuration["Authentication:JwtBearer:Issuer"];
        var audience = configuration["Authentication:JwtBearer:Audience"];
        var security = configuration["Authentication:JwtBearer:Security"];

        byte[] keys = Encoding.ASCII.GetBytes(security);

        return new JwtSettings(keys, issuer, audience);
    }
}