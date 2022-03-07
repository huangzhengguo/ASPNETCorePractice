namespace JWTSample.Models;

/// <summary>
/// 当期登录的用户信息
/// </summary>
public class CurrentUser
{
    public bool IsAuthenticated { get; set; }
    public int? UserId { get; set; }
    public string UserName { get; set; }
}