using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Public Key Algorithm tag numbers.</remarks>
    public enum PublicKeyAlgorithmTag
    {
        RsaGeneral = 1,			// RSA (Encrypt or Sign)
        RsaEncrypt = 2,			// RSA Encrypt-Only
        RsaSign = 3,			// RSA Sign-Only
        ElGamalEncrypt = 16,	// Elgamal (Encrypt-Only), see [ELGAMAL]
        Dsa = 17,				// DSA (Digital Signature Standard)
        ECDH = 18,              // Reserved for Elliptic Curve (actual algorithm name)
        ECDsa = 19,				// Reserved for ECDSA

        ElGamalGeneral = 20,	// Reserved (formerly Elgamal Encrypt or Sign)
        DiffieHellman = 21,		// Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)

        // TODO Mark obsolete once Ed25519, Ed448 available
        //[Obsolete("Use Ed25519 or Ed448 instead")]
        EdDsa = 22,             // EdDSA - (internet draft, but appearing in use)
        EdDsa_Legacy = 22,      // new name for old EdDSA tag.

        // defined as Reserved by RFC 9580
        AEDH = 23,
        AEDSA = 24,

        // https://www.rfc-editor.org/rfc/rfc9580
        X25519 = 25,
        X448 = 26,
        Ed25519 = 27,
        Ed448 = 28,

        // https://datatracker.ietf.org/doc/draft-ietf-openpgp-pqc/
        MLDsa65_Ed25519 = 30,
        MLDsa87_Ed448 = 31,
        SlhDsa_Shake128s = 32,
        SlhDsa_Shake128f = 33,
        SlhDsa_Shake256s = 34,
        MLKem768_X25519 = 35,
        MLKem1024_X448 = 36,

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
