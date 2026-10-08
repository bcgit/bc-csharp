using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.MLDsa65_Ed25519"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the Ed25519 secret key (32 octets) followed by the ML-DSA-65 secret key in seed format (the
    /// 32-octet value xi of ML-DSA.KeyGen).
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3.2.2">
    /// Post-Quantum Cryptography in OpenPGP - Secret Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLDsa65Ed25519SecretBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Ed25519Length = 32;
        public static readonly int MLDsaSeedLength = 32;
        public static readonly int Length = Ed25519Length + MLDsaSeedLength;

        public MLDsa65Ed25519SecretBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLDsa65Ed25519SecretBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the Ed25519 secret key component.</summary>
        public byte[] GetEd25519SecretKey() => Arrays.CopyOfRange(Key, 0, Ed25519Length);

        /// <summary>Return a copy of the ML-DSA-65 seed.</summary>
        public byte[] GetMLDsaSeed() => Arrays.CopyOfRange(Key, Ed25519Length, Length);
    }
}
