using System;
using System.Threading.Tasks;
using JWTSample.Models;

namespace JWTSample.Jwt;

public interface IStorageUserService
{
    Task<User> CheckPasswordAsync(LoginUserInfo loginUserInfo);
}

public class StorageUserService : IStorageUserService
{
    public async Task<User> CheckPasswordAsync(LoginUserInfo loginUserInfo)
    {
        return await Task.FromResult(new User
        {
            Id = new Random().Next(10000),
            Name = "用户" + new Random().Next(10000).ToString()
        });
    }
}