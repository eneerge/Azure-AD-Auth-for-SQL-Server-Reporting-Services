using Microsoft.ReportingServices.Interfaces;
using SSRS2016.OpenIDConnect.Security.AzureAuthentication;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Timers;
using System.Web;
using System.Web.Security;
using System.Web.Services.Protocols;
using System.Xml;

namespace SSRS2016.OpenIDConnect.Security
{
    public class SSRSAuthentication : IAuthenticationExtension2, IExtension
    {

        #region Static IdentityManagement
        // -------------------------------------------------------------------------------------------------------------------------------
        // -------------------------------------------------------------------------------------------------------------------------------
        public static ConcurrentDictionary<string, GCHandle> staticIdentities = new ConcurrentDictionary<string, GCHandle>();
        public static ConcurrentDictionary<string, DateTimeOffset> cleanUpList = new ConcurrentDictionary<string, DateTimeOffset>();
        static Timer cleanupTimer;

        static SSRSAuthentication()
        {
            cleanupTimer = new Timer(TimeSpan.FromMinutes(30).TotalMilliseconds);
            cleanupTimer.AutoReset = true;
            cleanupTimer.Elapsed += CleanupTimer_Elapsed;
            cleanupTimer.Start();
        }

        private static void CleanupTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            foreach (var cleanUp in cleanUpList)
            {
                if (cleanUp.Value < DateTimeOffset.Now)
                {
                    // Remove the Identity and Free the Handle so GC can Happen
                    GCHandle handle;
                    if (staticIdentities.TryRemove(cleanUp.Key, out handle))
                    {
                        handle.Free();
                    }

                    // Ensure the Item is removed from the cleanup list
                    DateTimeOffset expires;
                    cleanUpList.TryRemove(cleanUp.Key, out expires);
                }
            }
        }

        // -------------------------------------------------------------------------------------------------------------------------------
        // -------------------------------------------------------------------------------------------------------------------------------
        #endregion Static IdentityManagement


        // Configuration Items (read from rsreportserver.config Configuration File)
        //private string m_oidcAuthority;
        public string LocalizedName
        {
            get
            {
                return null;
            }
        }

        /// <summary>
        /// Returns a Handle whose Target is the Identity for the User
        /// </summary>
        /// <param name="username">Name of the user to get Identity For</param>
        /// <returns>Handle whose Target is a ClaimsIdentity</returns>
        private GCHandle GetIdentityHandle(string username, FormsAuthenticationTicket ticket)
        {
            GCHandle handle;
            if (!staticIdentities.TryGetValue(username, out handle))
            {
                // Ticket not null, setup claims using the ticket info and setup a new handle with those claims
                if (ticket != null)
                {
                    // Verify the JWT
                    if (ticket.UserData != null && ticket.UserData.Length > 0)
                    {
                        // This must be set
                        var ci = new ClaimsIdentity();
                        var claims = new List<Claim>();
                        claims.Add(new Claim(ClaimTypes.Name, username));

                        string[] groups = ticket.UserData.Split(',');
                        foreach (var g in groups)
                        {
                            claims.Add(new Claim(ClaimTypes.GroupSid, g));
                        }

                        ci.AddClaims(claims);
                        handle = GCHandle.Alloc(ci);
                    }
                }
                // No ticket info (probably temporary user), allocate a new blank handle with only the name claim
                else
                {
                    ClaimsIdentity ci = new ClaimsIdentity();
                    var claims = new List<Claim>();
                    claims.Add(new Claim(ClaimTypes.Name, username));
                    ci.AddClaims(claims);
                    handle = GCHandle.Alloc(ci);
                }

                // After allocation, try to add the handle to the staticidentities
                if (!staticIdentities.TryAdd(username, handle))
                {
                    // Someone else beat us to it - destroy this handle and the the one already there
                    if (!staticIdentities.TryGetValue(username, out handle))
                    {
                        throw new Exception("Unsupported Race Situation has occurred retrieving identity");
                    }
                }

            }

            // Make sure Expires is updated to 10 minutes from now
            var expiresAt = DateTimeOffset.Now.AddMinutes(10);
            cleanUpList.AddOrUpdate(username, expiresAt, (un, dt) => expiresAt);
            return handle;
        }

        /// <summary>
        /// Read the credentials from the Soap Request. 
        /// No longer used, but remains because the part that reads the XML stream may be something that is used in the future.
        /// </summary>
        /// <returns></returns>
        /*private UserCredential GetWebServiceCredential()
        {
            UserCredential cred = new UserCredential();

            // Read in the user credentials
            string xmlStream;
            using (System.IO.Stream receiveStream = HttpContext.Current.Request.InputStream)
            {
                using (StreamReader readStream = new StreamReader(receiveStream, Encoding.UTF8))
                {
                    xmlStream = readStream.ReadToEnd();
                }
            }

            // Get login info from the xml body
            if (!String.Empty.Equals(xmlStream))
            {
                XmlDocument xml = new XmlDocument();
                xml.LoadXml(xmlStream);
                var userXml = xml.GetElementsByTagName("userName"); // case sensitive
                if (userXml.Count == 1)
                {
                    cred.username = userXml.Item(0).InnerText;

                    // get password
                    var passXml = xml.GetElementsByTagName("password");
                    if (passXml.Count == 1)
                    {
                        cred.password = passXml.Item(0).InnerText;
                    }
                }
            }
            return cred;
        }*/

        /// <summary>
        /// Process requests to the web portal in a web browser. Create an AuthTicket.
        /// </summary>
        /// <param name="userIdentity"></param>
        /// <param name="userId"></param>
        private void ProcessWebPortalRequest(ref IIdentity userIdentity, ref IntPtr userId)
        {
            if (HttpContext.Current.User != null && HttpContext.Current.User.Identity != null)
            {
                GCHandle handle;
                FormsIdentity identity = (FormsIdentity)HttpContext.Current.User.Identity;
                FormsAuthenticationTicket ticket = (FormsAuthenticationTicket)identity.Ticket;

                handle = GetIdentityHandle(HttpContext.Current.User.Identity.Name, ticket);
                userIdentity = (ClaimsIdentity)handle.Target;
                userId = GCHandle.ToIntPtr(handle);
            }
            else
            {
                userIdentity = null;
                userId = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Process requests to the web service/asmx that occurs in  web browser, visual studio, or or web applications. No AuthTicket.
        /// </summary>
        /// <param name="userIdentity"></param>
        /// <param name="userId"></param>
        private void ProcessWebServiceRequest(ref IIdentity userIdentity, ref IntPtr userId)
        {
            if (HttpContext.Current.User != null)
            {
                GCHandle handle;
                //FormsIdentity identity = (FormsIdentity)HttpContext.Current.User.Identity;
                //FormsAuthenticationTicket ticket = (FormsAuthenticationTicket)identity.Ticket;


                handle = GetIdentityHandle(HttpContext.Current.User.Identity.Name, null);
                userIdentity = (ClaimsIdentity)handle.Target;
                userId = GCHandle.ToIntPtr(handle);
            }
            else
            {
                userIdentity = null;
                userId = IntPtr.Zero;
            }
        }

        public void GetUserInfo(out IIdentity userIdentity, out IntPtr userId)
        {
            userIdentity = null;
            userId = IntPtr.Zero;
            if (HttpContext.Current != null)
            {
                // Authentication for Visual Studio / Web Service
                if (HttpContext.Current.Request.CurrentExecutionFilePath.Contains("/ReportService2010.asmx")
                    || HttpContext.Current.Request.CurrentExecutionFilePath.Contains("/ReportService2006.asmx")
                    || HttpContext.Current.Request.CurrentExecutionFilePath.Contains("/ReportService2005.asmx")
                )
                {
                    ProcessWebServiceRequest(ref userIdentity, ref userId);
                }

                // Authentication for web portal
                else
                {
                    ProcessWebPortalRequest(ref userIdentity, ref userId);
                }
            }
        }

        public void GetUserInfo(IRSRequestContext requestContext, out IIdentity userIdentity, out IntPtr userId)
        {
            userIdentity = null;
            userId = IntPtr.Zero;

            if (requestContext.User != null)
            {
                FormsIdentity identity = (FormsIdentity)requestContext.User;
                FormsAuthenticationTicket ticket = (FormsAuthenticationTicket)identity.Ticket;

                var handle = GetIdentityHandle(requestContext.User.Name, ticket);
                userIdentity = (ClaimsIdentity)handle.Target;
                userId = GCHandle.ToIntPtr(handle);

            }
        }

        // TODO: Implement validation for the principal name to match email and group sids.
        /// <summary>
        /// Determines if a principal name is valid. Checked when entering new security groups for reports.
        /// </summary>
        /// <param name="principalName"></param>
        /// <returns></returns>
        public bool IsValidPrincipalName(string principalName)
        {
            return true;
        }

        /// <summary>
        /// Supports WebService Logins (via SSRS or calling the .asmx Web Services)
        /// </summary>
        /// <param name="userName">Username for the User</param>
        /// <param name="password">Password to verify with the Open Id Provider</param>
        /// <param name="authority">Not used if password is provided.  If no password is empty, a valid OIDC AccessToken can be sent here</param>
        /// <returns></returns>
        public bool LogonUser(string userName, string password, string authority)
        {
            // Get login info from the xml body
            if (userName != "" && password != "")
            {
                var oidcUtils = new AzureUtilities(
                    System.Configuration.ConfigurationManager.AppSettings["AzureAuthorityUri"]
                    ,System.Configuration.ConfigurationManager.AppSettings["AzureApplicationId"]
                    ,System.Configuration.ConfigurationManager.AppSettings["AzureClientSecret"]
                );
                var principal = oidcUtils.ValidateAzureUser(userName, password);

                // Auth success return true (authorization occurs later)
                if (principal.Identity.IsAuthenticated)
                {
                    HttpContext.Current.User = principal;

                    
                    // Remove the existing claims if it exists
                    GCHandle handle;
                    if (staticIdentities.TryGetValue(userName, out handle))
                    {
                        staticIdentities.TryRemove(userName, out handle);
                    }
                    // Add the latest claims in staticIdentities to the latest just retrieved
                    handle = GCHandle.Alloc(principal.Identity);
                    staticIdentities.TryAdd(userName, handle);

                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Called at Startup to Configure the Extension
        /// </summary>
        /// <param name="configuration"></param>
        public void SetConfiguration(string configuration)
        {

        }
    }
}