using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.MLKem1024_X448"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the X448 secret key (56 octets, native encoding) followed by the ML-KEM-1024 secret key in
    /// seed format (the 32-octet values d and z of ML-KEM.KeyGen, 64 octets in total).
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-4.3.2.2">
    /// Post-Quantum Cryptography in OpenPGP - Secret Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLKem1024X448SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int X448Length = 56;
        public static readonly int MLKemSeedLength = 64;
        public static readonly int Length = X448Length + MLKemSeedLength;

        public MLKem1024X448SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLKem1024X448SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the X448 secret key component.</summary>
        public byte[] GetX448SecretKey() => Arrays.CopyOfRange(Key, 0, X448Length);

        /// <summary>Return a copy of the ML-KEM-1024 seed (d || z).</summary>
        public byte[] GetMLKemSeed() => Arrays.CopyOfRange(Key, X448Length, Length);
    }
}
