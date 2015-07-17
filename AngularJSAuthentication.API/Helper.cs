using System.Diagnostics;
using System.Security.Principal;


namespace AngularJSAuthentication.API
{
    public static class Helper
    {
        public static void Write(string tag, IPrincipal principal)
        {

            Debug.WriteLine("-------- " + tag + " --------");
            if (principal == null || 
                principal.Identity == null ||
                !principal.Identity.IsAuthenticated)
            {
                Debug.WriteLine("anonymous user");
            } else {
                Debug.WriteLine("User: " + principal.Identity.Name);
            }
            Debug.WriteLine("\n");
        }
    }
}
