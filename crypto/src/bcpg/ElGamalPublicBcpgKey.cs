using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an ElGamal public key.</summary>
    public class ElGamalPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_p, m_g, m_y;

        public ElGamalPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            m_p = new MPInteger(bcpgIn);
            m_g = new MPInteger(bcpgIn);
            m_y = new MPInteger(bcpgIn);
        }

        public ElGamalPublicBcpgKey(BigInteger p, BigInteger g, BigInteger y)
        {
            m_p = new MPInteger(p);
            m_g = new MPInteger(g);
            m_y = new MPInteger(y);
        }

        public BigInteger P => m_p.Value;

        public BigInteger G => m_g.Value;

        public BigInteger Y => m_y.Value;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(this);

        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.WriteObjects(m_p, m_g, m_y);
    }
}
