using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Public key of type <see cref="PublicKeyAlgorithmTag.MLDsa87_Ed448"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the Ed448 public key (57 octets) followed by the ML-DSA-87 public key (2592 octets). This
    /// type was introduced with RFC 9980 and can only be used with v6 keys.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-5.3.2.1">
    /// Post-Quantum Cryptography in OpenPGP - Public Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class MLDsa87Ed448PublicBcpgKey
        : OctetArrayBcpgKey
    {
        public static readonly int Ed448Length = 57;
        public static readonly int MLDsaLength = 2592;
        public static readonly int Length = Ed448Length + MLDsaLength;

        public MLDsa87Ed448PublicBcpgKey(BcpgInputStream bcpgIn)
            : base(Length, bcpgIn)
        {
        }

        public MLDsa87Ed448PublicBcpgKey(byte[] key)
            : base(Length, key)
        {
        }

        /// <summary>Return a copy of the Ed448 public key component.</summary>
        public byte[] GetEd448PublicKey() => Arrays.CopyOfRange(Key, 0, Ed448Length);

        /// <summary>Return a copy of the ML-DSA-87 public key component.</summary>
        public byte[] GetMLDsaPublicKey() => Arrays.CopyOfRange(Key, Ed448Length, Length);
    }
}
