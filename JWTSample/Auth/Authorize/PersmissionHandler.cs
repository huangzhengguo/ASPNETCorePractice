using System.Threading.Tasks;
using System;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace JWTSample.Auth
{
    public class PersmissionHandler : AuthorizationHandler<PersmissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PersmissionRequirement requirement)
        {
            var isAuthenticated = context.User.Identity.IsAuthenticated;
            if (isAuthenticated)
            {
                var userName = Convert.ToString(context.User.FindFirst(c => c.Type == ClaimTypes.Name).Value);
                if (userName != null)
                {
                    context.Succeed(requirement);
                }
            }

            return Task.CompletedTask;
        }
    }
}