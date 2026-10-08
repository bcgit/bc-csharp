using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.MLKem1024_X448"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the X448 public key (56 octets) followed by the ML-KEM-1024 encapsulation key (1568 octets).
    /// This type was introduced with RFC 9980 and can only be used with v6 keys.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.3.2.1">
    /// Post-Quantum Cryptography in OpenPGP - Public Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLKem1024X448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int X448Length = 56;
        public static readonly int MLKemLength = 1568;
        public static readonly int Length = X448Length + MLKemLength;

        public MLKem1024X448PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLKem1024X448PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the X448 public key component.</summary>
        public byte[] GetX448PublicKey() => Arrays.CopyOfRange(Key, 0, X448Length);

        /// <summary>Return a copy of the ML-KEM-1024 encapsulation key component.</summary>
        public byte[] GetMLKemPublicKey() => Arrays.CopyOfRange(Key, X448Length, Length);
    }
}
