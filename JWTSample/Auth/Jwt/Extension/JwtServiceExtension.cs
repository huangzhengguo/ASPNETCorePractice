using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace JWTSample.Jwt;

public static class JwtServiceExtension
{
    /// <summary>
    /// 封装服务添加
    /// </summary>
    /// <param name="services">服务集合</param>
    /// <param name="configuration">配置</param>
    /// <returns></returns>
    public static IServiceCollection AddJwt(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        services.AddSingleton<IJwtService, JwtService>();

        var issuer = configuration[JwtOptionsConst.IssuerSettingPath];
        var audience = configuration[JwtOptionsConst.AudienceSettingPath];
        var security = configuration[JwtOptionsConst.SecurityKeySettingPath];

        var key = Encoding.ASCII.GetBytes(security);

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = true,

                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
        });

        return services;
    }
}