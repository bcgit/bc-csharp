using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for a DSA public key.</summary>
    public class DsaPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_p, m_q, m_g, m_y;

        /// <param name="bcpgIn">The stream to read the packet from.</param>
        public DsaPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            m_p = new MPInteger(bcpgIn);
            m_q = new MPInteger(bcpgIn);
            m_g = new MPInteger(bcpgIn);
            m_y = new MPInteger(bcpgIn);
        }

        public DsaPublicBcpgKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y)
        {
            m_p = new MPInteger(p);
            m_q = new MPInteger(q);
            m_g = new MPInteger(g);
            m_y = new MPInteger(y);
        }

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(this);

        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.WriteObjects(m_p, m_q, m_g, m_y);

        public BigInteger G => m_g.Value;

        public BigInteger P => m_p.Value;

        public BigInteger Q => m_q.Value;

        public BigInteger Y => m_y.Value;
    }
}
