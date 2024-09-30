using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace backend.Controllers
{
    [Authorize(Roles ="User")]
    [ApiController]
    [Route("api/[controller]")]
    public class User : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
          return Ok("You have accessed the User controller");
        }
    }
}