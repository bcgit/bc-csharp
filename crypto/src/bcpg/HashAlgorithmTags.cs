using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic tags for hash algorithms.</remarks>
    public enum HashAlgorithmTag
    {
        /// <summary>MD5.</summary>
        MD5 = 1,            // MD5
        /// <summary>SHA-1.</summary>
        Sha1 = 2,           // SHA-1
        /// <summary>RIPE-MD/160.</summary>
        RipeMD160 = 3,      // RIPE-MD/160
        /// <summary>Reserved for double-width SHA (experimental).</summary>
        DoubleSha = 4,      // Reserved for double-width SHA (experimental)
        /// <summary>MD2.</summary>
        MD2 = 5,            // MD2
        /// <summary>Reserved for TIGER/192.</summary>
        Tiger192 = 6,       // Reserved for TIGER/192
        /// <summary>Reserved for HAVAL (5 pass, 160-bit).</summary>
        Haval5pass160 = 7,  // Reserved for HAVAL (5 pass, 160-bit)

        /// <summary>SHA-256.</summary>
        Sha256 = 8,         // SHA-256
        /// <summary>SHA-384.</summary>
        Sha384 = 9,         // SHA-384
        /// <summary>SHA-512.</summary>
        Sha512 = 10,        // SHA-512
        /// <summary>SHA-224.</summary>
        Sha224 = 11,        // SHA-224
        /// <summary>SHA3-256.</summary>
        Sha3_256 = 12,      // SHA3-256
        /// <summary>SHA3-512.</summary>
        Sha3_512 = 14,      // SHA3-512

        [Obsolete("Non-standard")]
        /// <summary>The MD4 hash algorithm.</summary>
        MD4 = 301,
        [Obsolete("Non-standard")]
        /// <summary>SHA3-224.</summary>
        Sha3_224 = 312,     // SHA3-224
        [Obsolete("Non-standard")]
        /// <summary>SHA3-256.</summary>
        Sha3_256_Old = 313, // SHA3-256
        [Obsolete("Non-standard")]
        /// <summary>SHA3-384.</summary>
        Sha3_384 = 314,     // SHA3-384
        [Obsolete("Non-standard")]
        /// <summary>SHA3-512.</summary>
        Sha3_512_Old = 315, // SHA3-512

        [Obsolete("Non-standard")]
        /// <summary>SM3.</summary>
        SM3 = 326, // SM3
    }
}
