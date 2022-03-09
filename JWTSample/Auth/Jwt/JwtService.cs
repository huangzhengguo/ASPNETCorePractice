using System;
using System.Linq;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Http;

namespace JWTSample.Jwt;

/// <summary>
/// JWT 功能类
/// </summary>
public class JwtService : IJwtService
{
    // 获取 Http 上下文
    private readonly IHttpContextAccessor _httpContextAccessor;
    // 配置
    private readonly IConfiguration _configuration;
    public JwtService(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
    {
        _configuration = configuration;
        _httpContextAccessor = httpContextAccessor;
    }

    /// <summary>
    /// 生成 JWT
    /// </summary>
    /// <param name="userDto">用户信息</param>
    /// <returns></returns>
    public string GetnerateJWTToken(UserDto userDto)
    {
        var claims = new Claim[]
        {
            new Claim(ClaimTypes.Name, userDto.UserName),
            new Claim(ClaimTypes.Role, userDto.Roles),
            // 用户所在的分组
            new Claim("groups", userDto.Groups)
        };

        var issuer = _configuration[JwtOptionsConst.IssuerSettingPath];
        var audience = _configuration[JwtOptionsConst.AudienceSettingPath];
        var security = _configuration[JwtOptionsConst.SecurityKeySettingPath];
        var expires = DateTime.Now.AddHours(Convert.ToDouble(_configuration[JwtOptionsConst.ExpiresHourSettingPath]));

        SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(security));
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(claims: claims, issuer: issuer, audience: audience, expires: expires, signingCredentials: signingCredentials);
        var tokenHandler = new JwtSecurityTokenHandler();

        return tokenHandler.WriteToken(jwtSecurityToken);
    }

    /// <summary>
    /// 从 token 中解析用户信息
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public UserDto DecodeJWTToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        if (tokenHandler.CanReadToken(token))
        {
            JwtPayload jwtPayload = tokenHandler.ReadJwtToken(token).Payload;
            
            var userName = jwtPayload.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name).Value;
            var userGroups = jwtPayload.Claims.FirstOrDefault(c => c.Type == "groups").Value;
            var userRoles = jwtPayload.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role).Value;

            UserDto user = new UserDto();

            user.UserName = userName;
            user.Groups = userGroups;
            user.Roles = userRoles;

            return user;
        }

        return null;
    }

}