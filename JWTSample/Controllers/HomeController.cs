using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace JWTSample.Controllers;

[Authorize(Policy = "CustomPolicy")] // 使用策略授权
public class HomeController : Controller
{
    public HomeController()
    {

    }

    public IActionResult Index()
    {
        return View();
    }

    [AllowAnonymous]
    public IActionResult Login()
    {
        return View();
    }
}