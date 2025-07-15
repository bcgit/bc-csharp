using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an RSA public key.</summary>
    public class RsaPublicBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_n, m_e;

        /// <summary>Construct an RSA public key from the passed in stream.</summary>
        public RsaPublicBcpgKey(BcpgInputStream bcpgIn)
        {
            m_n = new MPInteger(bcpgIn);
            m_e = new MPInteger(bcpgIn);
        }

        /// <param name="n">The modulus.</param>
        /// <param name="e">The public exponent.</param>
        public RsaPublicBcpgKey(BigInteger n, BigInteger e)
        {
            m_n = new MPInteger(n);
            m_e = new MPInteger(e);
        }

        public BigInteger Modulus => m_n.Value;

        public BigInteger PublicExponent => m_e.Value;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(this);

        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.WriteObjects(m_n, m_e);
    }
}
