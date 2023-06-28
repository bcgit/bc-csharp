using System;

namespace Org.BouncyCastle.Bcpg
{
    public enum AeadAlgorithmTag : byte
    {
        Eax = 1,    // EAX (IV len: 16 octets, Tag len: 16 octets)
        Ocb = 2,    // OCB (IV len: 15 octets, Tag len: 16 octets)
        Gcm = 3,    // GCM (IV len: 12 octets, Tag len: 16 octets)
    }
}
