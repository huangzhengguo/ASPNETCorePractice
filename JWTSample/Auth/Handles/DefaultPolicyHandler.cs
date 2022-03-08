using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;
using JWTSample.Jwt;

namespace JWTSample.Auth.Handles
{
    public class DefaultPolicyHandler : AuthorizationHandler<DefaultPolicyRequirement>
    {
        private IAuthenticationSchemeProvider _schemeProvider;
        private IJwtService _jwtService;
        public DefaultPolicyHandler(IAuthenticationSchemeProvider schemeProvider, IJwtService jwtService)
        {
            _schemeProvider = schemeProvider;
            _jwtService = jwtService;
        }

        /// <summary>
        /// 授权处理
        /// </summary>
        /// <param name="context"></param>
        /// <param name="requirement"></param>
        /// <returns></returns>
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, DefaultPolicyRequirement requirement)
        {
            var httpContext = (context.Resource as AuthorizationFilterContext).HttpContext;

            // 获取授权方式
            var authorizationScheme = await _schemeProvider.GetDefaultAuthenticateSchemeAsync();
            if (authorizationScheme != null)
            {
                // 验证签发的用户信息
                var result = await httpContext.AuthenticateAsync(authorizationScheme.Name);
                if (result.Succeeded)
                {
                    // if (!await _jwtService.IsCurrentTokenValid())
                    // {
                    //     context.Fail();
                    //     return;
                    // }

                    httpContext.User = result.Principal;

                    // 判断是否过期
                    if (DateTime.Parse(httpContext.User.Claims.SingleOrDefault(s => s.Type == ClaimTypes.Expiration).Value) >= DateTime.UtcNow)
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        context.Fail();
                    }
                }

                return;
            }

            context.Fail();
        }
    }
}