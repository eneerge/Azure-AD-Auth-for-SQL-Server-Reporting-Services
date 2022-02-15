using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Runtime.Caching;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Web.Security;

namespace SSRS2016.OpenIDConnect.Security.AzureAuthentication
{
    /// <summary>
    /// Helper Class to Work with Open ID Connect Protocol
    /// </summary>
    public class AzureUtilities
    {
        const string CACHE_DISCO = "OIDC.CACHE.DISCO";

        /// <summary>
        /// OpenID Authority url excluding the ".well-known" path.
        /// EG: https://sts.windows.net/{tenant_id}/
        /// </summary>
        private string AzureAuthorityUri { get; set; }

        private string AzureApplicationId { get; set; }

        private string AzureClientSecret { get; set; }

        

        /// <summary>
        /// Helper class for communicating with OpenID identity server
        /// </summary>
        /// <param name="identityAuthorityUri"></param>
        /// <param name="identityApplicationId"></param>
        public AzureUtilities(string identityAuthorityUri, string identityApplicationId, string identityClientSecret)
        {
            // Clean up the url
            identityAuthorityUri = identityAuthorityUri.Trim();
            identityAuthorityUri = identityAuthorityUri.Trim('/');
            identityAuthorityUri += "/"; // ensure uri ends with a single slash
            
            this.AzureAuthorityUri = identityAuthorityUri;
            this.AzureApplicationId = identityApplicationId.Trim();
            this.AzureClientSecret = identityClientSecret.Trim();
        }

        /// <summary>
        /// Returns the .well-known/openid-configuration discovery address
        /// </summary>
        /// <returns></returns>
        public string GetDiscoveryAddress()
        {
            return this.AzureAuthorityUri + ".well-known/openid-configuration";
        }

        /// <summary>
        /// Returns the Open ID Connect Bearer Discovery Information
        /// </summary>
        /// <returns></returns>
        public DiscoveryDocumentResponse DiscoverOidcSettings()
        {
            // Not in memory cache, discover and cache
            if (!MemoryCache.Default.Contains(CACHE_DISCO))
            {
                var client = new System.Net.Http.HttpClient();
                client.BaseAddress = new Uri(GetDiscoveryAddress());

                DiscoveryDocumentRequest req = new DiscoveryDocumentRequest();

                // This must be disabled unless you have control of the identity server and can ensure the appropriate end point.
                // Microsoft Azure will not pass without this disabled. It is safe to disable.
                // https://github.com/IdentityModel/IdentityModel/issues/351
                DiscoveryPolicy pol = new DiscoveryPolicy();
                pol.ValidateEndpoints = false;
                req.Policy = pol;

                // Get discovery info
                var disco = client.GetDiscoveryDocumentAsync(req);
                DiscoveryDocumentResponse discoveryResponse = disco.Result;
                if (discoveryResponse == null || discoveryResponse.IsError)
                {
                    // TODO: Insert error into log and email administrator.
                    throw new Exception("Discovery Error. Erroroneus response returned from server.", discoveryResponse.Exception);
                }

                // Cache the discovery
                MemoryCache.Default.Add(CACHE_DISCO, discoveryResponse, DateTimeOffset.Now.AddHours(12));
            }

            return MemoryCache.Default[CACHE_DISCO] as DiscoveryDocumentResponse;
        }


        /// <summary>
        /// Builds a Login Uri to redirect the user for login
        /// </summary>
        /// <param name="state"></param>
        /// <param name="callback"></param>
        /// <returns></returns>
        public string BuildAuthorizeUrl(string state, string callback)
        {
            var nonce = Guid.NewGuid().ToString("N");
            MemoryCache.Default.Add(nonce, nonce, DateTimeOffset.Now.AddMinutes(10));
            var disco = DiscoverOidcSettings();
            var authorizeUrl = new RequestUrl(disco.AuthorizeEndpoint).CreateAuthorizeUrl(
                /* See https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-protocols-oidc and https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent */
                clientId: this.AzureApplicationId,
                responseType: "id_token",
                scope: "openid profile email",
                /*scope: "openid email",*/
                redirectUri: callback,
                state: state,
                nonce: nonce,
                responseMode: "form_post"
            );

            return authorizeUrl;
        }

        /// <summary>
        /// Validates an Identity Token
        /// </summary>
        /// <param name="idToken">The Received ID Token</param>
        /// <param name="NonceValidate">Validate Nonce - only works if Token was created from redirect after call to <see cref="BuildAuthorizeUrl(string, string)">BuildAuthorizeUrl</see>/></param>
        /// <returns></returns>
        public ClaimsPrincipal ValidateIdentityToken(string idToken, bool NonceValidate = true)
        {
            var user = ValidateJwt(idToken);

            var nonce = user.FindFirst("nonce")?.Value ?? "";
            if (NonceValidate && MemoryCache.Default[nonce] as string != nonce)
                throw new Exception("invalid nonce");

            return user;
        }

        /// <summary>
        
        /// </summary>
        /// <param name="jwt">the JWT Token</param>
        /// <returns></returns>
        private ClaimsPrincipal ValidateJwt(string jwt)
        {
            // read discovery document to find issuer and key material
            var disco = DiscoverOidcSettings();

            var keys = new List<SecurityKey>();
            foreach (var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n })
                {
                    KeyId = webKey.Kid
                };

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidAudience = this.AzureApplicationId,
                IssuerSigningKeys = keys,

                // ValidateIssuer could potentially cause errors if the discovery document is not configured properly. Uncomment below to troubleshoot. However, for security purposes, don't use this in production.
                // ValidateIssuer = false,
                
                ValidIssuers = new List<string>()
                {
                    disco.Issuer // Get issuer from the discovery request
                    // ,"https://login.windows.net/{tenant_id}/v2.0" // other valid azure issuers
                    // ,"https://login.microsoftonline.com/{tenant_id}/v2.0"
                },
                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role
            };
            
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            //Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true; // This will show detailed debugging info if an error occurs during jwt validation, but this should not be set to true in production.
            var user = handler.ValidateToken(jwt, parameters, out var _);
            return user;
        }

        /// <summary>
        /// Generates an Authentication Ticket so that it can be passed across requests.
        /// The groups and email address available in the ClaimsPrincipal will be stored in the ticket for future authorization purposes.
        /// NOTE: User is NOT reauthenticated on each request, so if their access is revoked in Azure, their access to SSRS will not be revoked when the AuthTicket expires.
        ///       Need to consider repulling the Claims of the user on each request - just store the id_token and then reauthenticate against the id_token instead of "caching" the user's claims.
        /// This ticket is decoded with each request to the web portal.
        /// This is not and should not be used for web service / visual studio authentication.
        /// </summary>
        /// <param name="principal">The ClaimsPrinciple that was returned from the identity provider</param>
        /// <returns></returns>
        public FormsAuthenticationTicket GenerateAuthTicket(ClaimsPrincipal principal)
        {
            if (principal != null && principal.Identity != null && principal.Identity.Name != null)
            {

                // Enhancement/TODO: Should just store the id_token instead of pulling out the groups and then reauth the id_token on each request.

                var groups = "";
                var email = "";

                // Loop through the claims in the principal and grab the group sids and the email address so they can be used for authorization
                foreach (var c in principal.Claims)
                {
                    // Group SID
                    if (c.Type.Equals("groups"))
                    {
                        groups += c.Value + ",";
                    }
                    // v1.0 api, UPN will likely be the user's email address when email scope is not used
                    else if (c.Type.Equals("upn"))
                    {
                        if (c.Value.Contains("@"))
                        {
                            groups += c.Value + ",";
                            email = c.Value;
                        }
                    }
                    // V2.0 api will return an email claim as long as "email" is provided into the scope parameter in the BuildAuthorizeUrl
                    else if (c.Type.Equals("email"))
                    {
                        groups += c.Value + ",";
                        email = c.Value;
                    }
                }
                groups = groups.Trim(',');


                // Include the group and email info in the auth ticket's userdata
                FormsAuthenticationTicket ticket;
                if (email.Equals(""))
                {
                    // No email found, base ticket on the principal identity name which should be Firstname Lastname if come directly from Azure
                    ticket = new FormsAuthenticationTicket(1, principal.Identity.Name, DateTime.Now, DateTime.Now.AddMinutes(30), true, groups);
                }
                else
                {
                    // Base the ticket on the user's email address (This is the name that will appear in the top right corner of the SSRS web portal)
                    ticket = new FormsAuthenticationTicket(1, email, DateTime.Now, DateTime.Now.AddMinutes(30), true, groups);
                }

                return ticket;
            }

            // Unknown path
            throw new Exception("Principal parameter was null. Perhaps no claims principal was returned from the identity provider.");
        }


        /// <summary>
        /// This method attempts to login to Azure using username and password authentication. This method of authentication is not recommended by Azure documentation, but we are only using it for authenticating Visual Studio report deployments. 
        /// This method is not utilized for SSRS web portal authentication. Web portal requests use the recommended interactive login.
        /// NOTE: This will not work if you have 2FA/MFA enabled. In that case, you will need to create another Azure user that is not MFA enabled to deploy reports.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public ClaimsPrincipal ValidateAzureUser(string username, string password)
        {
            var disco = DiscoverOidcSettings();

            var client = new System.Net.Http.HttpClient();
            client.BaseAddress = new Uri(disco.TokenEndpoint);

            var response = client.RequestPasswordTokenAsync(new PasswordTokenRequest
            {
                ClientId = this.AzureApplicationId,
                ClientSecret = this.AzureClientSecret,
                Scope = "openid profile email",

                UserName = username,
                Password = password,
                GrantType = "password" // MFA enabled users can not login when when using password type. see: https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc
            });

            var jwt = response.Result.IdentityToken;
            var principal = ValidateIdentityToken(jwt, false);

            return principal;
        }
    }
}
