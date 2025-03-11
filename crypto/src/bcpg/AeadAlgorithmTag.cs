using System;

namespace Org.BouncyCastle.Bcpg
{
    public enum AeadAlgorithmTag : byte
    {
        Eax = 1,    // EAX (IV len: 16 octets, Tag len: 16 octets)
        Ocb = 2,    // OCB (IV len: 15 octets, Tag len: 16 octets)
        Gcm = 3,    // GCM (IV len: 12 octets, Tag len: 16 octets)

        Experimental_1 = 100,
        Experimental_2 = 101,
        Experimental_3 = 102,
        Experimental_4 = 103,
        Experimental_5 = 104,
        Experimental_6 = 105,
        Experimental_7 = 106,
        Experimental_8 = 107,
        Experimental_9 = 108,
        Experimental_10 = 109,
        Experimental_11 = 110,
    }
}
