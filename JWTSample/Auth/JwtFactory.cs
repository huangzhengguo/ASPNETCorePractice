using System;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Collections.Generic;
using System.Security.Principal;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using System.Text.Json;
using JWTSample.Models;

namespace JWTSample.Auth
{
    public interface IJwtFactory
    {
        Task<string> GenerateEncodedToken(string userName, ClaimsIdentity identity);
        ClaimsIdentity GenerateClaimsIdentity(User user);
    }
    
    public class JwtFactory : IJwtFactory
    {
        private readonly JwtIssuerOptions _jwtOptions;

        public JwtFactory(IOptions<JwtIssuerOptions> jwtOptions)
        {
            _jwtOptions = jwtOptions.Value;
            ThrowIfInvalidOptions(_jwtOptions);
        }

        public async Task<string> GenerateEncodedToken(string userName, ClaimsIdentity identity)
        {
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, userName),
                new Claim(JwtRegisteredClaimNames.Jti, await _jwtOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(_jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                identity.FindFirst(ClaimTypes.Name),
                identity.FindFirst("id")
            };

            claims.AddRange(identity.FindAll(ClaimTypes.Role));

            var jwt = new JwtSecurityToken(
                issuer: _jwtOptions.Issuer,
                audience: _jwtOptions.Audience,
                claims: claims,
                notBefore: _jwtOptions.NotBefore,
                expires: _jwtOptions.Expiration,
                signingCredentials: _jwtOptions.SigningCredentials
            );

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                token = encodedJwt,
                expries_in = (int)_jwtOptions.ValidFor.TotalSeconds,
                token_type = "Bearer"
            };

            var serializationOption = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            return JsonSerializer.Serialize(response, serializationOption);
        }

        public ClaimsIdentity GenerateClaimsIdentity(User user)
        {
            var claimsIdentity = new ClaimsIdentity(new GenericIdentity(user.Name, "Token"));

            claimsIdentity.AddClaim(new Claim("id", user.Id.ToString()));
            claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, user.Name));

            foreach(var role in user.Role.Split(','))
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role));
            }

            return claimsIdentity;
        }

        private static long ToUnixEpochDate(DateTime dateTime)
        {
            return (long)Math.Round((dateTime.ToUniversalTime() - 
                    new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
        }

        private static void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor < TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(options.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(options.JtiGenerator));
            }
        }
    }
}