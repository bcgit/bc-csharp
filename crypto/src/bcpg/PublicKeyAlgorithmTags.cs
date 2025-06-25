using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Public Key Algorithm tag numbers.</remarks>
    public enum PublicKeyAlgorithmTag
    {
        RsaGeneral = 1,			// RSA (Encrypt or Sign)
        /// <remarks>Use RsaGeneral instead</remarks>
        RsaEncrypt = 2,			// RSA Encrypt-Only
        /// <remarks>Use RsaGeneral instead</remarks>
        RsaSign = 3,			// RSA Sign-Only
        ElGamalEncrypt = 16,	// Elgamal (Encrypt-Only), see [ELGAMAL]
        Dsa = 17,				// DSA (Digital Signature Standard)
        ECDH = 18,              // Reserved for Elliptic Curve (actual algorithm name)
        ECDsa = 19,				// Reserved for ECDSA
        /// <remarks>Use ElGamalEncrypt instead</remarks>
        ElGamalGeneral = 20,	// Elgamal (Encrypt or Sign)
        DiffieHellman = 21,		// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)

        [Obsolete("Use 'EdDsa_Legacy' instead")]
        EdDsa = 22,             // EdDSA - (internet draft, but appearing in use)
        EdDsa_Legacy = 22,      // new name for old EdDSA tag.

        X25519 = 25,            // X25519 encryption algorithm
        X448 = 26,              // X448 encryption algorithm

        Ed25519 = 27,           // new style Ed25519 signing algorithm
        Ed448 = 28,             // new style Ed448 signing algorithm

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
