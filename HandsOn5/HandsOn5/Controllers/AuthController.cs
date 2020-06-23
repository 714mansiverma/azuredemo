using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace HandsOn5.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        [HttpPost("JWT")]
        public IActionResult JWT()
        {
            var header = Request.Headers["Authorization"];
            if (header.ToString().StartsWith("Basic"))
            {
                var credValue = header.ToString().Substring("Basic".Length).Trim();
                var usernameAndPass = Encoding.UTF8.GetString(Convert.FromBase64String(credValue));
                var detail = usernameAndPass.Split(":");
                //string token = "asdfg";

                if (detail[0] == "Admin" & detail[1] == "1234")
                {
                    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("asdfghjklzxcvbnm"));
                    var signCredential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
                    var claimsdata = new[] { new Claim(ClaimTypes.Name, detail[0]) };

                    var token = new JwtSecurityToken(
                         issuer: "trile.com",
                         audience: "trile.com",
                         expires: DateTime.Now.AddMinutes(2),
                         claims: claimsdata,
                         signingCredentials: signCredential
                        );

                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                    return Ok(tokenString);
                }
            }
            return BadRequest("Wrong Request");
        }
    }
}