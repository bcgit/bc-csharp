using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    // TODO[api] Don't implement ICipherParameters
    public class DHParameters
        : ICipherParameters
    {
        private const int DefaultMinimumLength = 160;

        private readonly BigInteger m_p, m_g, m_q, m_j;
        private readonly int m_m, m_l;
        private readonly DHValidationParameters m_validation;

        private static int GetDefaultMParam(int lParam) =>
            lParam == 0 ? DefaultMinimumLength : System.Math.Min(lParam, DefaultMinimumLength);

        public DHParameters(BigInteger p, BigInteger g)
            : this(p, g, q: null)
        {
        }

        public DHParameters(BigInteger p, BigInteger g, BigInteger q)
            : this(p, g, q, l: 0)
        {
        }

        public DHParameters(BigInteger p, BigInteger g, BigInteger q, int l)
            : this(p, g, q, m: GetDefaultMParam(l), l)
        {
        }

        public DHParameters(BigInteger p, BigInteger g, BigInteger q, int m, int l)
            : this(p, g, q, m, l, j: null, validation: null)
        {
        }

        public DHParameters(BigInteger p, BigInteger g, BigInteger q, BigInteger j, DHValidationParameters validation)
            : this(p, g, q, m: DefaultMinimumLength, l: 0, j, validation)
        {
        }

        public DHParameters(BigInteger p, BigInteger g, BigInteger q, int m, int l, BigInteger j,
            DHValidationParameters validation)
        {
            if (p == null)
                throw new ArgumentNullException(nameof(p));
            if (g == null)
                throw new ArgumentNullException(nameof(g));
            if (!p.TestBit(0))
                throw new ArgumentException("field must be an odd prime", nameof(p));
            if (g.CompareTo(BigInteger.Two) < 0 || g.CompareTo(p.Subtract(BigInteger.Two)) > 0)
                throw new ArgumentException("generator must in the range [2, p - 2]", nameof(g));
            if (q != null && q.BitLength >= p.BitLength)
                throw new ArgumentException("q too big to be a factor of (p-1)", nameof(q));
            if (m >= p.BitLength)
                throw new ArgumentException("m value must be < bitlength of p", nameof(m));
            if (l != 0)
            {
                if (l >= p.BitLength)
                    throw new ArgumentException("when l value specified, it must be less than bitlength(p)", nameof(l));
                if (l < m)
                    throw new ArgumentException("when l value specified, it may not be less than m value", nameof(l));
            }
            if (j != null && j.CompareTo(BigInteger.Two) < 0)
                throw new ArgumentException("subgroup factor must be >= 2", nameof(j));

            // TODO If q, j both provided, validate p = jq + 1 ?

            m_p = p;
            m_g = g;
            m_q = q;
            m_m = m;
            m_l = l;
            m_j = j;
            m_validation = validation;
        }

        public BigInteger P => m_p;

        public BigInteger G => m_g;

        public BigInteger Q => m_q;

        public BigInteger J => m_j;

        /// <summary>The minimum bitlength of the private value.</summary>
        public int M => m_m;

        /// <summary>The bitlength of the private value.</summary>
        public int L => m_l;

        public DHValidationParameters ValidationParameters => m_validation;

        public override bool Equals(object obj)
        {
            if (obj == this)
                return true;

            return obj is DHParameters that
                && Equals(that);
        }

        protected virtual bool Equals(DHParameters other)
        {
            return m_p.Equals(other.m_p)
                && m_g.Equals(other.m_g)
                && Objects.Equals(m_q, other.m_q);
        }

        public override int GetHashCode()
        {
            int hc = m_p.GetHashCode() ^ m_g.GetHashCode();

            if (m_q != null)
            {
                hc ^= m_q.GetHashCode();
            }

            return hc;
        }
    }
}
