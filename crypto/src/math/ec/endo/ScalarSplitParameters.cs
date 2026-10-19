using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public class ScalarSplitParameters
    {
        private static void CheckVector(BigInteger[] v, string name)
        {
            if (v == null || v.Length != 2 || v[0] == null || v[1] == null)
                throw new ArgumentException("Must consist of exactly 2 (non-null) values", name);
        }

        protected readonly BigInteger m_v1A, m_v1B, m_v2A, m_v2B;
        protected readonly BigInteger m_g1, m_g2;
        protected readonly int m_bits;

        /// <summary>Create a new <see cref="ScalarSplitParameters"/>.</summary>
        /// <param name="v1">The v 1.</param>
        /// <param name="v2">The v 2.</param>
        /// <param name="g1">The g 1.</param>
        /// <param name="g2">The g 2.</param>
        /// <param name="bits">The bits.</param>
        public ScalarSplitParameters(BigInteger[] v1, BigInteger[] v2, BigInteger g1,
            BigInteger g2, int bits)
        {
            CheckVector(v1, "v1");
            CheckVector(v2, "v2");

            this.m_v1A = v1[0];
            this.m_v1B = v1[1];
            this.m_v2A = v2[0];
            this.m_v2B = v2[1];
            this.m_g1 = g1;
            this.m_g2 = g2;
            this.m_bits = bits;
        }

        /// <summary>Gets the v 1 a.</summary>
        public virtual BigInteger V1A
        {
            get { return m_v1A; }
        }

        /// <summary>Gets the v 1 b.</summary>
        public virtual BigInteger V1B
        {
            get { return m_v1B; }
        }

        /// <summary>Gets the v 2 a.</summary>
        public virtual BigInteger V2A
        {
            get { return m_v2A; }
        }

        /// <summary>Gets the v 2 b.</summary>
        public virtual BigInteger V2B
        {
            get { return m_v2B; }
        }

        /// <summary>Gets the g 1.</summary>
        public virtual BigInteger G1
        {
            get { return m_g1; }
        }

        /// <summary>Gets the g 2.</summary>
        public virtual BigInteger G2
        {
            get { return m_g2; }
        }

        /// <summary>Gets the bits.</summary>
        public virtual int Bits
        {
            get { return m_bits; }
        }
    }
}
