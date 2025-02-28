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
    public BasicAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
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

    private bool ValidateCredentials(string username, string password)
    {
        // For now, we'll just check if username is "admin" and password is "password"
        // Replace this with your actual validation logic (e.g., database lookup)
        return username == "admin" && password == "password";
    }
}
