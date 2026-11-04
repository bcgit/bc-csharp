using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an ElGamal secret key.</summary>
    public class ElGamalSecretBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_x;

        /// <summary>Create a new <see cref="ElGamalSecretBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public ElGamalSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            m_x = new MPInteger(bcpgIn);
        }

        /// <summary>Create a new <see cref="ElGamalSecretBcpgKey"/>.</summary>
        /// <param name="x">The first operand.</param>
        public ElGamalSecretBcpgKey(BigInteger x)
        {
            m_x = new MPInteger(x);
        }

        /// <summary>Gets the x.</summary>
        public BigInteger X => m_x.Value;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(m_x);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) => m_x.Encode(bcpgOut);
    }
}
