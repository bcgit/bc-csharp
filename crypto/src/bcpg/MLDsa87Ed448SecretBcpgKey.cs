using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.MLDsa87_Ed448"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the Ed448 secret key (57 octets) followed by the ML-DSA-87 secret key in seed format (the
    /// 32-octet value xi of ML-DSA.KeyGen).
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3.2.2">
    /// Post-Quantum Cryptography in OpenPGP - Secret Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLDsa87Ed448SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Ed448Length = 57;
        public static readonly int MLDsaSeedLength = 32;
        public static readonly int Length = Ed448Length + MLDsaSeedLength;

        public MLDsa87Ed448SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLDsa87Ed448SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the Ed448 secret key component.</summary>
        public byte[] GetEd448SecretKey() => Arrays.CopyOfRange(Key, 0, Ed448Length);

        /// <summary>Return a copy of the ML-DSA-87 seed.</summary>
        public byte[] GetMLDsaSeed() => Arrays.CopyOfRange(Key, Ed448Length, Length);
    }
}
