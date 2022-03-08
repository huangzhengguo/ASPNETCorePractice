using System;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using JWTSample.Jwt;
using JWTSample.Models;

namespace JWTSample.Controllers;

public class AuthController : Controller
{
    private readonly IJwtService _jwtService;

    public AuthController(IJwtService jwtService)
    {
        _jwtService = jwtService;
    }

    [AllowAnonymous]
    [HttpPost]
    public IActionResult Login([FromBody] LoginUserInfo loginUserInfo)
    {
        if (loginUserInfo.Name == null)
        {
            return Ok(new
            {
                Message = "用户名不能为空!"
            });
        }

        var userDto = new UserDto()
        {
            UserId = new Random().Next(1000),
            UserName = loginUserInfo.Name,
            Groups = "技术部",
            Roles = "软件工程师",
            Email = "123456789@qq.com",
            Phone = "123456789"
        };
        var token = _jwtService.GetnerateJWTToken(userDto);

        return Ok(new
        {
            Token = token
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