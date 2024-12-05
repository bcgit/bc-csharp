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
        public const int dh = 1;
        public const int ecdh = 2;
        public const int ecdsa = 3;
        public const int kem = 4;
    }
}
