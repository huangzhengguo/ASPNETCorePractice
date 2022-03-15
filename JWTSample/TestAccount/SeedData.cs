using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace JWTSample.Auth;

public class SeedData
{
    /// <summary>
    /// 根据密码和用户名确认创建用户成功
    /// </summary>
    /// <param name="serviceProvider"></param>
    /// <param name="testUserPassword"></param>
    /// <param name="userName"></param>
    /// <returns></returns>
    private static async Task<string> EnsureUser(IServiceProvider serviceProvider, string testUserPassword, string userName)
    {
        var userManager = serviceProvider.GetService<UserManager<IdentityUser>>();

        var user = await userManager.FindByNameAsync(userName);
        if (user == null)
        {
            user = new IdentityUser()
            {
                UserName = userName,
                EmailConfirmed = true
            };

            await userManager.CreateAsync(user, testUserPassword);
        }

        if (user == null)
        {
            throw new Exception("密码强度可能不够!");
        }

        return user.Id;
    }

    /// <summary>
    /// 根据用户id 和 角色，添加角色信息到用户
    /// </summary>
    /// <param name="serviceProvider"></param>
    /// <param name="uid"></param>
    /// <param name="role"></param>
    /// <returns></returns>
    private static async Task<IdentityResult> EnsureRole(IServiceProvider serviceProvider, string uid, string role)
    {
        var roleManager = serviceProvider.GetService<RoleManager<IdentityRole>>();
        if (roleManager == null)
        {
            throw new Exception("角色管理为空!");
        }

        IdentityResult ir;
        if (!await roleManager.RoleExistsAsync(role))
        {
            ir = await roleManager.CreateAsync(new IdentityRole(role));
        }

        var userManager = serviceProvider.GetService<UserManager<IdentityUser>>();

        var user = await userManager.FindByIdAsync(uid);
        if (user == null)
        {
            throw new Exception("密码可能不够强壮!");
        }

        ir = await userManager.AddToRoleAsync(user, role);

        return ir;
    }
}