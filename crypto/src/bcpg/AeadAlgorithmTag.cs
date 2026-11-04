using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>The AEAD algorithms of OpenPGP.</summary>
    public enum AeadAlgorithmTag : byte
    {
        /// <summary>EAX (IV len: 16 octets, Tag len: 16 octets).</summary>
        Eax = 1,    // EAX (IV len: 16 octets, Tag len: 16 octets)
        /// <summary>OCB (IV len: 15 octets, Tag len: 16 octets).</summary>
        Ocb = 2,    // OCB (IV len: 15 octets, Tag len: 16 octets)
        /// <summary>GCM (IV len: 12 octets, Tag len: 16 octets).</summary>
        Gcm = 3,    // GCM (IV len: 12 octets, Tag len: 16 octets)
    }
}
