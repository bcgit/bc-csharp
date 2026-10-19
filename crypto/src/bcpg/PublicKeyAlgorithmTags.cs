using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Public Key Algorithm tag numbers.</remarks>
    public enum PublicKeyAlgorithmTag
    {
        /// <summary>RSA (Encrypt or Sign).</summary>
        RsaGeneral = 1, // RSA (Encrypt or Sign)
        /// <remarks>Use RsaGeneral instead</remarks>
        RsaEncrypt = 2, // RSA Encrypt-Only
        /// <remarks>Use RsaGeneral instead</remarks>
        RsaSign = 3, // RSA Sign-Only
        /// <summary>Elgamal (Encrypt-Only), see [ELGAMAL].</summary>
        ElGamalEncrypt = 16, // Elgamal (Encrypt-Only), see [ELGAMAL]
        /// <summary>DSA (Digital Signature Standard).</summary>
        Dsa = 17, // DSA (Digital Signature Standard)
        /// <summary>Reserved for Elliptic Curve (actual algorithm name).</summary>
        ECDH = 18,              // Reserved for Elliptic Curve (actual algorithm name)
        /// <summary>Reserved for ECDSA.</summary>
        ECDsa = 19, // Reserved for ECDSA
        /// <remarks>Use ElGamalEncrypt instead</remarks>
        ElGamalGeneral = 20, // Elgamal (Encrypt or Sign)
        /// <summary>Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME).</summary>
        DiffieHellman = 21, // Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)

        [Obsolete("Use 'EdDsa_Legacy' instead")]
        /// <summary>EdDSA - (internet draft, but appearing in use).</summary>
        EdDsa = 22,             // EdDSA - (internet draft, but appearing in use)
        /// <summary>New name for old EdDSA tag.</summary>
        EdDsa_Legacy = 22,      // new name for old EdDSA tag.

        /// <summary>X25519 encryption algorithm.</summary>
        X25519 = 25,            // X25519 encryption algorithm
        /// <summary>X448 encryption algorithm.</summary>
        X448 = 26,              // X448 encryption algorithm

        /// <summary>New style Ed25519 signing algorithm.</summary>
        Ed25519 = 27,           // new style Ed25519 signing algorithm
        /// <summary>New style Ed448 signing algorithm.</summary>
        Ed448 = 28,             // new style Ed448 signing algorithm

        /// <summary>Experimental public key algorithm number 1.</summary>
        Experimental_1 = 100,
        /// <summary>Experimental public key algorithm number 2.</summary>
        Experimental_2 = 101,
        /// <summary>Experimental public key algorithm number 3.</summary>
        Experimental_3 = 102,
        /// <summary>Experimental public key algorithm number 4.</summary>
        Experimental_4 = 103,
        /// <summary>Experimental public key algorithm number 5.</summary>
        Experimental_5 = 104,
        /// <summary>Experimental public key algorithm number 6.</summary>
        Experimental_6 = 105,
        /// <summary>Experimental public key algorithm number 7.</summary>
        Experimental_7 = 106,
        /// <summary>Experimental public key algorithm number 8.</summary>
        Experimental_8 = 107,
        /// <summary>Experimental public key algorithm number 9.</summary>
        Experimental_9 = 108,
        /// <summary>Experimental public key algorithm number 10.</summary>
        Experimental_10 = 109,
        /// <summary>Experimental public key algorithm number 11.</summary>
        Experimental_11 = 110,
    }
}
