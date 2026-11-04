using System;

namespace Org.BouncyCastle.Tls
{
    /// <summary>RFC 2246</summary>
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values(e.g.serialization).
    /// </remarks>
    public abstract class ConnectionEnd
    {
        /// <summary>The <c>server</c> constant, with the value <c>0</c>.</summary>
        public const int server = 0;
        /// <summary>The <c>client</c> constant, with the value <c>1</c>.</summary>
        public const int client = 1;
    }
}
