using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.MLKem768_X25519"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the X25519 public key (32 octets) followed by the ML-KEM-768 encapsulation key (1184
    /// octets). This type was introduced with RFC 9980 and can be used with v4 encryption subkeys and v6 keys.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.3.2.1">
    /// Post-Quantum Cryptography in OpenPGP - Public Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLKem768X25519PublicBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int X25519Length = 32;
        public static readonly int MLKemLength = 1184;
        public static readonly int Length = X25519Length + MLKemLength;

        public MLKem768X25519PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLKem768X25519PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the X25519 public key component.</summary>
        public byte[] GetX25519PublicKey() => Arrays.CopyOfRange(Key, 0, X25519Length);

        /// <summary>Return a copy of the ML-KEM-768 encapsulation key component.</summary>
        public byte[] GetMLKemPublicKey() => Arrays.CopyOfRange(Key, X25519Length, Length);
    }
}
