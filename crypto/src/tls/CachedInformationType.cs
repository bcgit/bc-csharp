using System;

namespace Org.BouncyCastle.Tls
{
    public abstract class CachedInformationType
    {
        /// <summary>The <c>cert</c> constant, with the value <c>1</c>.</summary>
        public const short cert = 1;
        /// <summary>The <c>cert_req</c> constant, with the value <c>2</c>.</summary>
        public const short cert_req = 2;

        public static string GetName(short cachedInformationType)
        {
            switch (cachedInformationType)
            {
            case cert:
                return "cert";
            case cert_req:
                return "cert_req";
            default:
                return "UNKNOWN";
            }
        }

        public static string GetText(short cachedInformationType)
        {
            return GetName(cachedInformationType) + "(" + cachedInformationType + ")";
        }
    }
}
