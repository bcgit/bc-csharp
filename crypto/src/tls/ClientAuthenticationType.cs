using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>Constants for the client authentication types of RFC 5077 section 4.</summary>
    public abstract class ClientAuthenticationType
    {
        /*
         * RFC 5077 4
         */
        public const short anonymous = 0;
        /// <summary>The <c>certificate_based</c> constant, with the value <c>1</c>.</summary>
        public const short certificate_based = 1;
        /// <summary>The <c>psk</c> constant, with the value <c>2</c>.</summary>
        public const short psk = 2;
    }
}
