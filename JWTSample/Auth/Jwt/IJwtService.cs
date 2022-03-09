using System.Threading.Tasks;

namespace JWTSample.Jwt;

/// <summary>
/// Jwt 功能接口
/// </summary>
public interface IJwtService
{
    // 生成 JWT token
    string GetnerateJWTToken(UserDto userDto);
    // 解析 JWT token
    UserDto DecodeJWTToken(string token);
}