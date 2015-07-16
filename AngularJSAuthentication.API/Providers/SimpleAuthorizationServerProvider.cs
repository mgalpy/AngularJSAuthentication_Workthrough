using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace AngularJSAuthentication.API.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //always return that its validated successfully FOR NOW until we implement propper logic
            context.Validated();

            //// POSSIBLE EXAMPLE ON VALIDATION OF SPECIFIC CREDENTIALS

            ////string clientId = string.Empty;
            ////string clientSecret = string.Empty;

            ////if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            ////{
            ////    context.SetError("invalid_client", "Client credentials could not be retrieved through the Authorization header.");
            ////    context.Rejected();
            ////    return;
            ////}

            ////ApplicationDatabaseContext dbContext = context.OwinContext.Get<ApplicationDatabaseContext>();
            ////ApplicationUserManager userManager = context.OwinContext.GetUserManager<ApplicationUserManager>();

            ////if (dbContext == null)
            ////{
            ////    context.SetError("server_error");
            ////    context.Rejected();
            ////    return;
            ////}

            ////try
            ////{
            ////    AppClient client = await dbContext
            ////        .Clients
            ////        .FirstOrDefaultAsync(clientEntity => clientEntity.Id == clientId);

            ////    if (client != null && userManager.PasswordHasher.VerifyHashedPassword(client.ClientSecretHash, clientSecret) == PasswordVerificationResult.Success)
            ////    {
            ////        // Client has been verified.
            ////        context.OwinContext.Set<AppClient>("oauth:client", client);
            ////        context.Validated(clientId);
            ////    }
            ////    else
            ////    {
            ////        // Client could not be validated.
            ////        context.SetError("invalid_client", "Client credentials are invalid.");
            ////        context.Rejected();
            ////    }
            ////}
            ////catch (Exception ex)
            ////{
            ////    string errorMessage = ex.Message;
            ////    context.SetError("server_error");
            ////    context.Rejected();
            ////}
        }

        //validate the username and password sent to the authorization server’s token endpoint
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            //To allow CORS on the token middleware provider
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            using (AuthRepository _repo = new AuthRepository())
            {
                IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

                if (user == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim("role", "user"));

            //generating the token
            context.Validated(identity);

        }
    }
}
