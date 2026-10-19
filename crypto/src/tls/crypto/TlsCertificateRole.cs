using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Constants for the roles a certificate can play in a TLS connection.</summary>
    public abstract class TlsCertificateRole
    {
        /// <summary>The <c>DH</c> constant, with the value <c>1</c>.</summary>
        public const int DH = 1;
        /// <summary>The <c>ECDH</c> constant, with the value <c>2</c>.</summary>
        public const int ECDH = 2;
        /// <summary>The <c>RsaEncryption</c> constant, with the value <c>3</c>.</summary>
        public const int RsaEncryption = 3;
        /// <summary>The <c>Sm2Encryption</c> constant, with the value <c>4</c>.</summary>
        public const int Sm2Encryption = 4;
    }
}
