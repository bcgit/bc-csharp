using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an ElGamal public key.</summary>
    public class ElGamalPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_p, m_g, m_y;

        /// <summary>Create a new <see cref="ElGamalPublicBcpgKey"/>.</summary>
        /// <param name="bcpgIn">The stream to read the encoding from.</param>
        public ElGamalPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            m_p = new MPInteger(bcpgIn);
            m_g = new MPInteger(bcpgIn);
            m_y = new MPInteger(bcpgIn);
        }

        /// <summary>Create a new <see cref="ElGamalPublicBcpgKey"/>.</summary>
        /// <param name="p">The prime modulus.</param>
        /// <param name="g">The generator.</param>
        /// <param name="y">The second operand.</param>
        public ElGamalPublicBcpgKey(BigInteger p, BigInteger g, BigInteger y)
        {
            m_p = new MPInteger(p);
            m_g = new MPInteger(g);
            m_y = new MPInteger(y);
        }

        /// <summary>Gets the p.</summary>
        public BigInteger P => m_p.Value;

        /// <summary>Gets the g.</summary>
        public BigInteger G => m_g.Value;

        /// <summary>Gets the y.</summary>
        public BigInteger Y => m_y.Value;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(this);

        /// <inheritdoc/>
        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.WriteObjects(m_p, m_g, m_y);
    }
}
