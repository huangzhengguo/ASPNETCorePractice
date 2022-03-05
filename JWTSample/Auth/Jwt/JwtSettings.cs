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

    
}