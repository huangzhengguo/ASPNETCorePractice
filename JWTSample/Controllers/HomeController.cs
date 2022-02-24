using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

namespace JWTSample.Controllers;

[Authorize]
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
    public IActionResult NoNeedAuthentication()
    {
        return View();
    }
}