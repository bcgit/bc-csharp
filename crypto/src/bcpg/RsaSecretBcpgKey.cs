using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <summary>Base class for an RSA secret (or private) key.</summary>
    public class RsaSecretBcpgKey
        : BcpgObject, IBcpgKey
    {
        private readonly MPInteger m_d, m_p, m_q, m_u;
        private readonly BigInteger m_expP, m_expQ, m_crt;

        public RsaSecretBcpgKey(BcpgInputStream bcpgIn)
        {
            m_d = new MPInteger(bcpgIn);
            m_p = new MPInteger(bcpgIn);
            m_q = new MPInteger(bcpgIn);
            m_u = new MPInteger(bcpgIn);

            m_expP = m_d.Value.Remainder(m_p.Value.Subtract(BigInteger.One));
            m_expQ = m_d.Value.Remainder(m_q.Value.Subtract(BigInteger.One));
            m_crt = BigIntegers.ModOddInverse(m_p.Value, m_q.Value);
        }

        public RsaSecretBcpgKey(BigInteger d, BigInteger p, BigInteger q)
        {
            // PGP requires (p < q)
            int cmp = p.CompareTo(q);
            if (cmp >= 0)
            {
                if (cmp == 0)
                    throw new ArgumentException("p and q cannot be equal");

                BigInteger tmp = p;
                p = q;
                q = tmp;
            }

            m_d = new MPInteger(d);
            m_p = new MPInteger(p);
            m_q = new MPInteger(q);
            m_u = new MPInteger(BigIntegers.ModOddInverse(q, p));

            m_expP = d.Remainder(p.Subtract(BigInteger.One));
            m_expQ = d.Remainder(q.Subtract(BigInteger.One));
            m_crt = BigIntegers.ModOddInverse(p, q);
        }

        public BigInteger Modulus => m_p.Value.Multiply(m_q.Value);

        public BigInteger PrivateExponent => m_d.Value;

        public BigInteger PrimeP => m_p.Value;

        public BigInteger PrimeQ => m_q.Value;

        public BigInteger PrimeExponentP => m_expP;

        public BigInteger PrimeExponentQ => m_expQ;

        public BigInteger CrtCoefficient => m_crt;

        /// <summary>The format, as a string, always "PGP".</summary>
        public string Format => "PGP";

        /// <summary>Return the standard PGP encoding of the key.</summary>
        public override byte[] GetEncoded() => BcpgOutputStream.GetEncodedOrNull(this);

        public override void Encode(BcpgOutputStream bcpgOut) => bcpgOut.WriteObjects(m_d, m_p, m_q, m_u);
    }
}
