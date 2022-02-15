using SSRS2016.OpenIDConnect.Security.AzureAuthentication;
using System;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Web.Security;

namespace SSRS2016.OpenIDConnect.Security
{
    public class OidcLogon : System.Web.UI.Page
    {
        override protected void OnInit(EventArgs e)
        {
            InitializeComponent();
            base.OnInit(e);
        }

        private void InitializeComponent()
        {
            this.Load += new System.EventHandler(this.Page_Load);

        }
        private void Page_Load(object sender, System.EventArgs e)
        {
            var AzureAuthorityUri = System.Configuration.ConfigurationManager.AppSettings["AzureAuthorityUri"];
            var AzureApplicationId = System.Configuration.ConfigurationManager.AppSettings["AzureApplicationId"];
            var AzureClientSecret = System.Configuration.ConfigurationManager.AppSettings["AzureClientSecret"];

            if (Request.HttpMethod.Equals("get", StringComparison.OrdinalIgnoreCase))
            {
                var oidcUtils = new AzureUtilities(AzureAuthorityUri, AzureApplicationId, AzureClientSecret);

                // Store Return Url in State
                var state = Convert.ToBase64String(Encoding.UTF8.GetBytes(Request.QueryString["ReturnUrl"]));

                // URL must be clean (no QueryString, etc)
                var callbackBuilder = new UriBuilder(Request.Url.AbsoluteUri);
                callbackBuilder.Query = null;
                var callback = callbackBuilder.Uri.AbsoluteUri;

                Response.Redirect(oidcUtils.BuildAuthorizeUrl(state, callback), true);
            }

            // Post parameters set, check for OpenID id_token
            if (Request.HttpMethod.Equals("post", StringComparison.OrdinalIgnoreCase))
            {
                if (Request.Form["state"] != null && Request.Form["id_token"] != null)
                {
                    var oidcUtils = new AzureUtilities(AzureAuthorityUri, AzureApplicationId, AzureClientSecret);
                 
                    // Pull out state and token
                    var origUrl = Encoding.UTF8.GetString(Convert.FromBase64String(Request.Form["state"]));
                    var idToken = Request.Form["id_token"];

                    // Validate token and get the user principal
                    var principal = oidcUtils.ValidateIdentityToken(idToken);
                    var ticket = oidcUtils.GenerateAuthTicket(principal);
                    
                    // Store ticket in cookie
                    string cookiestr = FormsAuthentication.Encrypt(ticket);
                    HttpCookie ck = new HttpCookie(FormsAuthentication.FormsCookieName, cookiestr);
                    Response.Cookies.Add(ck);

                    // Route to app
                    Response.Redirect(origUrl, true);
                }

                // If authentication failed or if there is some other error, then redirect to the azure error url.
                //TODO: Create a better authentication error page.
                if (Request.Form["error_uri"] != null)
                {
                    Response.Redirect(Request.Form["error_uri"], true);
                }
            }
        }
    }
}