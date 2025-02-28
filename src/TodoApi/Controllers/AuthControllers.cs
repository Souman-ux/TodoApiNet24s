using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace TodoApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        // For demo purposes, use in-memory "user store".
        // In production, you'd query a database for users and hash passwords securely.
        private static readonly Dictionary<string, string> _users = new Dictionary<string, string>
        {
            { "admin", "password" },
            { "user", "userpassword" }
        };

        // POST: api/auth/login
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            if (loginRequest == null || string.IsNullOrEmpty(loginRequest.Username) || string.IsNullOrEmpty(loginRequest.Password))
            {
                return BadRequest("Username and password are required.");
            }

            if (_users.ContainsKey(loginRequest.Username) && _users[loginRequest.Username] == loginRequest.Password)
            {
                // For simplicity, let's return a success message with a fake token.
                // In a real scenario, you would generate and return a JWT token here.
                var token = GenerateFakeToken(loginRequest.Username);

                return Ok(new { Token = token });
            }
            else
            {
                return Unauthorized("Invalid username or password.");
            }
        }
        [HttpPost("register")]
        public IActionResult Register([FromBody] RegisterModel model)
        {
            if (UserStore.GetUser(model.Username) != null)
            {
                return Conflict("Пользователь с таким логином уже существует");
            }



            return Ok("Пользователь зарегистрирован");
        }

        // Fake token generator (for demo purposes only)
        private string GenerateFakeToken(string username)
        {
            return $"{username}_fake_token_{System.Guid.NewGuid()}";
        }
    }

    // Request model for login

    public class RegisterModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
