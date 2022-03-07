using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JWTSample.Jwt;
using JWTSample.Models;

namespace JWTSample.Controllers;

public class AuthController : Controller
{
    private readonly IStorageUserService _storageUserService;
    private readonly JwtSettings _jwtSettings;

    public AuthController(IStorageUserService storageUserService, JwtSettings jwtSettings)
    {
        _storageUserService = storageUserService;
        _jwtSettings = jwtSettings;
    }

    /// <summary>
    /// 生成 JWT token
    /// </summary>
    /// <param name="loginUserInfo"></param>
    /// <returns></returns>
    [HttpPost]
    public async Task<IActionResult> GenerateJWTToke([FromBody] LoginUserInfo loginUserInfo)
    {
        // 检测用户密码
        var user = await _storageUserService.CheckPasswordAsync(loginUserInfo);
        if (user == null)
        {
            return Ok(new
            {
                Code = 1,
                Message = "用户登录失败!"
            });
        }

        // 生成 token
        var claims = new List<Claim>();

        claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        claims.Add(new Claim(ClaimTypes.Name, user.Name));

        var key = new SymmetricSecurityKey(_jwtSettings.Key);
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(issuer: _jwtSettings.Issuer, audience: _jwtSettings.Audience, claims, DateTime.Now.AddMinutes(30), signingCredentials:creds);

        return Ok(new
        {
            Code = 0,
            Token = new JwtSecurityTokenHandler().WriteToken(token)
        });
    }

    /// <summary>
    /// 解析 JWT
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public CurrentUser DecodeJWTToken(string token)
    {
        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        if (jwtSecurityTokenHandler.CanReadToken(token))
        {
            JwtPayload jwtPayload = jwtSecurityTokenHandler.ReadJwtToken(token).Payload;
            string userId = jwtPayload.Claims.FirstOrDefault(m => m.Type == ClaimTypes.NameIdentifier).Value;
            string userName = jwtPayload.Claims.FirstOrDefault(m => m.Type == ClaimTypes.Name).Value;
            CurrentUser currentUser = new CurrentUser
            {
                // IsAuthenticated = true,
                UserId = userId == null ? null : Convert.ToInt32(userId),
                UserName = userName
            };

            return currentUser;
        }

        return null;
    }
}