namespace JWTSample.Jwt;

/// <summary>
/// 配置路径常量
/// </summary>
public static class JwtOptionsConst
{
    public readonly static string IssuerSettingPath = "Authentication:JwtBearer:Issuer";
    public readonly static string AudienceSettingPath = "Authentication:JwtBearer:Audience";
    public readonly static string ExpiresHourSettingPath = "Authentication:JwtBearer:ExpiresHour";
    public readonly static string SecurityKeySettingPath = "Authentication:JwtBearer:SecurityKey";
}