using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246</summary>
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values (e.g. serialization).
    /// </remarks>
    public abstract class CipherType
    {
        /// <summary>The <c>stream</c> constant, with the value <c>0</c>.</summary>
        public const int stream = 0;
        /// <summary>The <c>block</c> constant, with the value <c>1</c>.</summary>
        public const int block = 1;

        /*
         * RFC 5246
         */
        public const int aead = 2;
    }
}
