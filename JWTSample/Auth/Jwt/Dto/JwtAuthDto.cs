namespace JWTSample.Jwt
{
    /// <summary>
    /// JWT传输对象
    /// </summary>
    public class JwtAuthDto
    {
        /// <summary>
        /// 授权时间
        /// </summary>
        /// <value></value>
        public long AuthTime { get; set; }

        /// <summary>
        /// 过期时间
        /// </summary>
        /// <value></value>
        public long Expires { get; set; }

        /// <summary>
        /// 授权是否成功
        /// </summary>
        /// <value></value>
        public bool Success { get; set; }

        /// <summary>
        /// 错误码：成功返回 20000
        /// </summary>
        /// <value></value>
        public int Code { get; set; }

        /// <summary>
        /// Token
        /// </summary>
        /// <value></value>
        public string Token { get; set; }

        /// <summary>
        /// 用户主键
        /// </summary>
        /// <value></value>
        public int UserId { get; set; }
    }
}