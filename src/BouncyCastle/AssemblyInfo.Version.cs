using System;
using System.Reflection;

[assembly: CLSCompliant(true)]

internal class AssemblyInfo
{
   private static string version = null;

   public static string Version
   {
      get
      {
         if (version == null)
         {

            version = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            // if we're still here, then don't try again
            if (version == null)
            {
               version = string.Empty;
            }
         }

         return version;
      }
   }
}
