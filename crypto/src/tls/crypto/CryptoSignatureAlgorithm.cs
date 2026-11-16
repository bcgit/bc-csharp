using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Constants for the signature algorithms known to the TLS crypto layer.</summary>
    public abstract class CryptoSignatureAlgorithm
    {
        /// <summary>The <c>rsa</c> constant, with the value <c>1</c>.</summary>
        public const int rsa = 1;
        /// <summary>The <c>dsa</c> constant, with the value <c>2</c>.</summary>
        public const int dsa = 2;
        /// <summary>The <c>ecdsa</c> constant, with the value <c>3</c>.</summary>
        public const int ecdsa = 3;
        /// <summary>The <c>rsa_pss_rsae_sha256</c> constant, with the value <c>4</c>.</summary>
        public const int rsa_pss_rsae_sha256 = 4;
        /// <summary>The <c>rsa_pss_rsae_sha384</c> constant, with the value <c>5</c>.</summary>
        public const int rsa_pss_rsae_sha384 = 5;
        /// <summary>The <c>rsa_pss_rsae_sha512</c> constant, with the value <c>6</c>.</summary>
        public const int rsa_pss_rsae_sha512 = 6;
        /// <summary>The <c>ed25519</c> constant, with the value <c>7</c>.</summary>
        public const int ed25519 = 7;
        /// <summary>The <c>ed448</c> constant, with the value <c>8</c>.</summary>
        public const int ed448 = 8;
        /// <summary>The <c>rsa_pss_pss_sha256</c> constant, with the value <c>9</c>.</summary>
        public const int rsa_pss_pss_sha256 = 9;
        /// <summary>The <c>rsa_pss_pss_sha384</c> constant, with the value <c>10</c>.</summary>
        public const int rsa_pss_pss_sha384 = 10;
        /// <summary>The <c>rsa_pss_pss_sha512</c> constant, with the value <c>11</c>.</summary>
        public const int rsa_pss_pss_sha512 = 11;
        /// <summary>The <c>ecdsa_brainpoolP256r1tls13_sha256</c> constant, with the value <c>26</c>.</summary>
        public const int ecdsa_brainpoolP256r1tls13_sha256 = 26;
        /// <summary>The <c>ecdsa_brainpoolP384r1tls13_sha384</c> constant, with the value <c>27</c>.</summary>
        public const int ecdsa_brainpoolP384r1tls13_sha384 = 27;
        /// <summary>The <c>ecdsa_brainpoolP512r1tls13_sha512</c> constant, with the value <c>28</c>.</summary>
        public const int ecdsa_brainpoolP512r1tls13_sha512 = 28;
        /// <summary>The <c>gostr34102012_256</c> constant, with the value <c>64</c>.</summary>
        public const int gostr34102012_256 = 64;
        /// <summary>The <c>gostr34102012_512</c> constant, with the value <c>65</c>.</summary>
        public const int gostr34102012_512 = 65;
        /// <summary>The <c>sm2</c> constant, with the value <c>200</c>.</summary>
        public const int sm2 = 200;
    }
}
