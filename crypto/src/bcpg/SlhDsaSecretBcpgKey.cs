using System;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Secret key of type <see cref="PublicKeyAlgorithmTag.SlhDsa_Shake128s"/>, <see
    /// cref="PublicKeyAlgorithmTag.SlhDsa_Shake128f"/> or <see cref="PublicKeyAlgorithmTag.SlhDsa_Shake256s"/>.
    /// </summary>
    /// <remarks>
    /// The key material is the SLH-DSA secret key (SK.seed || SK.prf || PK.seed || PK.root) in the encoding of FIPS
    /// 205: 64 octets for SLH-DSA-SHAKE-128s and -128f, 128 octets for SLH-DSA-SHAKE-256s.
    /// <para>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9980.html#section-6.2.2.2">
    /// Post-Quantum Cryptography in OpenPGP - Secret Key Packets
    /// </see>
    /// </para>
    /// </remarks>
    public sealed class SlhDsaSecretBcpgKey
        : OctetArrayBcpgKey
    {
        /// <summary>Return the length of the key material for the given algorithm, in octets.</summary>
        /// <exception cref="ArgumentException">If the algorithm is not an SLH-DSA algorithm.</exception>
        public static int GetKeyLength(PublicKeyAlgorithmTag algorithm)
        {
            switch (algorithm)
            {
            case PublicKeyAlgorithmTag.SlhDsa_Shake128s:
            case PublicKeyAlgorithmTag.SlhDsa_Shake128f:
                return 64;
            case PublicKeyAlgorithmTag.SlhDsa_Shake256s:
                return 128;
            default:
                throw new ArgumentException("Not an SLH-DSA algorithm: " + algorithm, nameof(algorithm));
            }
        }

        public SlhDsaSecretBcpgKey(PublicKeyAlgorithmTag algorithm, byte[] key)
            : base(GetKeyLength(algorithm), key)
        {
        }

        internal SlhDsaSecretBcpgKey(PublicKeyAlgorithmTag algorithm, BcpgInputStream bcpgIn)
            : base(GetKeyLength(algorithm), bcpgIn)
        {
        }
    }
}
