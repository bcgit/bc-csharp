using System;

namespace Org.BouncyCastle.Tls
{
    /// <remarks>
    /// Note that the values here are implementation-specific and arbitrary. It is recommended not to depend on the
    /// particular values (e.g. serialization).
    /// </remarks>
    // TODO[api] Make static
    public abstract class NamedGroupRole
    {
        /// <summary>The <c>dh</c> constant, with the value <c>1</c>.</summary>
        public const int dh = 1;
        /// <summary>The <c>ecdh</c> constant, with the value <c>2</c>.</summary>
        public const int ecdh = 2;
        /// <summary>The <c>ecdsa</c> constant, with the value <c>3</c>.</summary>
        public const int ecdsa = 3;
        /// <summary>The <c>kem</c> constant, with the value <c>4</c>.</summary>
        public const int kem = 4;
    }
}
