using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IUserRepository _userRepository;  // Interface for accessing user data (for password reset)
    private readonly EmailService _emailService;      // Service to send the email with reset link

    public BasicAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        IUserRepository userRepository,   // Dependency injection for user repository
        EmailService emailService)        // Dependency injection for email service
        : base(options, logger, encoder, clock)
    {
        _userRepository = userRepository;
        _emailService = emailService;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorizationHeader = Request.Headers["Authorization"];

        if (string.IsNullOrEmpty(authorizationHeader))
        {
            return Task.FromResult(AuthenticateResult.Fail("Missing Authorization Header"));
        }

        try
        {
            // Extract username and password from the Authorization header
            var authHeader = authorizationHeader.ToString();
            var credentials = DecodeCredentials(authHeader);

            if (credentials == null || !ValidateCredentials(credentials.Item1, credentials.Item2))
            {
                return Task.FromResult(AuthenticateResult.Fail("Invalid Username or Password"));
            }

            // Create ClaimsPrincipal for a successful authentication
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, credentials.Item1)
            };

            var identity = new ClaimsIdentity(claims, "Basic");
            var principal = new ClaimsPrincipal(identity);

            var ticket = new AuthenticationTicket(principal, "BasicAuthentication");

            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        catch (Exception ex)
        {
            return Task.FromResult(AuthenticateResult.Fail(ex.Message));
        }
    }

    // Method for forgot password
    public async Task<IActionResult> ForgotPassword(string username)
    {
        var user = await _userRepository.GetUserByUsernameAsync(username);

        if (user == null)
        {
            return new BadRequestObjectResult("User not found.");
        }

        // Generate reset token and expiration time (1 hour)
        var resetToken = Guid.NewGuid().ToString();
        user.ResetToken = resetToken;
        user.ResetTokenExpiration = DateTime.UtcNow.AddHours(1);

        await _userRepository.UpdateUserAsync(user);

        // Send the password reset link via email (simulate sending email here)
        var resetLink = $"https://yourapp.com/reset-password?token={resetToken}";
        await _emailService.SendPasswordResetEmailAsync(user.Username, resetLink);

        return new OkObjectResult(new { Message = "Password reset link sent to your email." });
    }

    // Method for resetting the password
    public async Task<IActionResult> ResetPassword(string resetToken, string newPassword)
    {
        var user = await _userRepository.GetUserByResetTokenAsync(resetToken);

        if (user == null || user.ResetTokenExpiration < DateTime.UtcNow)
        {
            return new BadRequestObjectResult("Invalid or expired reset token.");
        }

        // Hash the new password
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword);

        // Clear the reset token after resetting the password
        user.ResetToken = null;
        user.ResetTokenExpiration = null;

        await _userRepository.UpdateUserAsync(user);

        return new OkObjectResult("Password has been successfully reset.");
    }

    // Method to decode credentials from the Authorization header
    private Tuple<string, string> DecodeCredentials(string authorizationHeader)
    {
        if (!authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var base64Credentials = authorizationHeader.Substring("Basic ".Length).Trim();
        var decodedBytes = Convert.FromBase64String(base64Credentials);
        var decodedString = System.Text.Encoding.UTF8.GetString(decodedBytes);

        var parts = decodedString.Split(':');
        if (parts.Length == 2)
        {
            return Tuple.Create(parts[0], parts[1]);
        }

        return null;
    }

    // Basic credentials validation
    private bool ValidateCredentials(string username, string password)
    {
        // For simplicity, assume "admin" is the valid username and "password" is the valid password
        // Replace this with actual validation logic, like database checks
        return username == "admin" && password == "password";
    }
}
