using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.MLDsa65_Ed25519"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the Ed25519 public key (32 octets) followed by the ML-DSA-65 public key (1952 octets). This
    /// type was introduced with RFC 9980 and can only be used with v6 keys.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3.2.1">
    /// Post-Quantum Cryptography in OpenPGP - Public Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLDsa65Ed25519PublicBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Ed25519Length = 32;
        public static readonly int MLDsaLength = 1952;
        public static readonly int Length = Ed25519Length + MLDsaLength;

        public MLDsa65Ed25519PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLDsa65Ed25519PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the Ed25519 public key component.</summary>
        public byte[] GetEd25519PublicKey() => Arrays.CopyOfRange(Key, 0, Ed25519Length);

        /// <summary>Return a copy of the ML-DSA-65 public key component.</summary>
        public byte[] GetMLDsaPublicKey() => Arrays.CopyOfRange(Key, Ed25519Length, Length);
    }
}
