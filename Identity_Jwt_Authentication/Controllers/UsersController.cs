using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Identity_Jwt_Authentication.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.IdentityModel.Tokens.Jwt;

namespace Identity_Jwt_Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsersController : ControllerBase
    {
        private UserManager<UsersModel> _userManager;
        private SignInManager<UsersModel> _signinManager;
        private readonly JWT _JWT;
        public UsersController(UserManager<UsersModel> userManager, SignInManager<UsersModel> signinManager,IOptions<JWT> JWT)
        {
            _userManager = userManager;
            _signinManager = signinManager;
            _JWT = JWT.Value;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<object> Register(RegisterModel Model) {
            try
            {
                var user = new UsersModel()
                {
                    UserName=Model.UserName,
                    Email=Model.Email,
                    PhoneNumber=Model.PhoneNumber
                };
                 var result = await _userManager.CreateAsync(user,Model.Password);
           
                return result;
            }catch(Exception ex)
            {
                throw ex;
            }
        }
        [HttpPost]
        [Route("Auth")]
        public async Task <IActionResult> Auth(LoginModel Model)
        {
            try
            {
                var key = System.Text.Encoding.UTF8.GetBytes(_JWT.Key);
                var user=await _userManager.FindByNameAsync(Model.UserName);
                if ((user!=null) && (await _userManager.CheckPasswordAsync(user, Model.Password))){
                    var tokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow.AddDays(1),
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                            new Claim(ClaimTypes.NameIdentifier, user.UserName),
                            new Claim("UserID", user.Id.ToString())
                        }),
                        SigningCredentials = new SigningCredentials( new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha384Signature)
                    };
                    var tokenHandler = new JwtSecurityTokenHandler();
                    var tokensecurity = tokenHandler.CreateToken(tokenDescriptor);
                    var token = tokenHandler.WriteToken(tokensecurity);
          
                    return Ok(new {token });
                }
                else
                {
                    var userfailed = await _userManager.FindByNameAsync(Model.UserName);
                   await  _userManager.AccessFailedAsync(userfailed);
                    return BadRequest();
                }
           
               
            } 
            catch(Exception ex)
            {
                throw ex;
            }
        }
    }
}
