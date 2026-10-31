using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.MLKem768_X25519"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the X25519 secret key (32 octets, native little-endian encoding) followed by the
    /// ML-KEM-768 secret key in seed format (the 32-octet values d and z of ML-KEM.KeyGen, 64 octets in total).
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.3.2.2">
    /// Post-Quantum Cryptography in OpenPGP - Secret Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLKem768X25519SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int X25519Length = 32;
        public static readonly int MLKemSeedLength = 64;
        public static readonly int Length = X25519Length + MLKemSeedLength;

        public MLKem768X25519SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLKem768X25519SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the X25519 secret key component.</summary>
        public byte[] GetX25519SecretKey() => Arrays.CopyOfRange(Key, 0, X25519Length);

        /// <summary>Return a copy of the ML-KEM-768 seed (d || z).</summary>
        public byte[] GetMLKemSeed() => Arrays.CopyOfRange(Key, X25519Length, Length);
    }
}
