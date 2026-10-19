using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 5246 7.2</summary>
    public abstract class AlertLevel
    {
        /// <summary>The <c>warning</c> constant, with the value <c>1</c>.</summary>
        public const short warning = 1;
        /// <summary>The <c>fatal</c> constant, with the value <c>2</c>.</summary>
        public const short fatal = 2;

        /// <summary>Get the name of the given alert description.</summary>
        /// <param name="alertDescription">The alert description.</param>
        /// <returns>The name.</returns>
        public static string GetName(short alertDescription)
        {
            switch (alertDescription)
            {
            case warning:
                return "warning";
            case fatal:
                return "fatal";
            default:
                return "UNKNOWN";
            }
        }

        /// <summary>
        /// Get a textual representation of the given alert description, made up of its name and its numeric value.
        /// </summary>
        /// <param name="alertDescription">The alert description.</param>
        /// <returns>The text.</returns>
        public static string GetText(short alertDescription)
        {
            return GetName(alertDescription) + "(" + alertDescription + ")";
        }
    }
}
