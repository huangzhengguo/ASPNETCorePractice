using System;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using JWTSample.Models;

namespace JWTSample.Jwt;

public interface IStorageUserService
{
    Task<User> CheckPasswordAsync(LoginUserInfo loginUserInfo);
    // 根据请求头获取用户信息
    Task<CurrentUser> GetUserByRequestContext();
}

public class StorageUserService : IStorageUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public StorageUserService(IHttpContextAccessor httpContextAccessor)
    {
        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<User> CheckPasswordAsync(LoginUserInfo loginUserInfo)
    {
        return await Task.FromResult(new User
        {
            Id = new Random().Next(10000),
            Name = "用户" + new Random().Next(10000).ToString()
        });
    }

    /// <summary>
    /// 通过请求头获取用户信息
    /// </summary>
    /// <returns></returns>
    public async Task<CurrentUser> GetUserByRequestContext()
    {
        var user = _httpContextAccessor.HttpContext.User;

        string userId = user.Claims.FirstOrDefault(m => m.Type == ClaimTypes.NameIdentifier).Value;
        string userName = user.Claims.FirstOrDefault(m => m.Type == ClaimTypes.Name).Value;
        CurrentUser currentUser = new CurrentUser
        {
            IsAuthenticated = user.Identity.IsAuthenticated,
            UserId = userId == null ? null : Convert.ToInt32(userId),
            UserName = userName  
        };

        return await Task.FromResult(currentUser);
    }
}