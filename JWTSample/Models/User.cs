using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ComponentModel.DataAnnotations;

namespace JWTSample.Models
{
    /// <summary>
    /// 用户
    /// </summary>
    [Serializable]
    public class User
    {
        public int Id { get; set; }

        /// <summary>
        /// 用户名
        /// </summary>
        [Display(Name = "用户名")]
        [StringLength(32)]
        public string Name { get; set; }

        /// <summary>
        /// 性别
        /// </summary>
        [Display(Name = "性别")]
        [StringLength(32)]
        public string Gender { get; set; }

        /// <summary>
        /// 用户分组
        /// </summary>
        [Display(Name = "用户分组")]
        [StringLength(32)]
        public string Group { get; set; }

        /// <summary>
        /// 角色,使用逗号分隔多个角色
        /// </summary>
        [Display(Name = "角色")]
        [StringLength(32)]
        public string Role { get; set; }

        /// <summary>
        /// 密码
        /// </summary>
        [Display(Name = "密码")]
        [StringLength(255)]
        public string Password { get; set; }

        /// <summary>
        /// 密码
        /// </summary>
        [Display(Name = "密码")]
        [StringLength(255)]
        public string Password2 { get; set; }

        /// <summary>
        /// 登录时间
        /// </summary>
        [Display(Name = "登录时间")]
        public DateTime? LoginDateTime { get; set; }
    }
}
