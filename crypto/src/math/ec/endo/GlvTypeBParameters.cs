using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public class GlvTypeBParameters
    {
        protected readonly BigInteger m_beta, m_lambda;
        protected readonly ScalarSplitParameters m_splitParams;

        [Obsolete("Use constructor taking a ScalarSplitParameters instead")]
        public GlvTypeBParameters(BigInteger beta, BigInteger lambda, BigInteger[] v1, BigInteger[] v2,
            BigInteger g1, BigInteger g2, int bits)
        {
            this.m_beta = beta;
            this.m_lambda = lambda;
            this.m_splitParams = new ScalarSplitParameters(v1, v2, g1, g2, bits);
        }

        public GlvTypeBParameters(BigInteger beta, BigInteger lambda, ScalarSplitParameters splitParams)
        {
            this.m_beta = beta;
            this.m_lambda = lambda;
            this.m_splitParams = splitParams;
        }

        public virtual BigInteger Beta
        {
            get { return m_beta; }
        }

        public virtual BigInteger Lambda
        {
            get { return m_lambda; }
        }

        public virtual ScalarSplitParameters SplitParams
        {
            get { return m_splitParams; }
        }

        [Obsolete("Access via SplitParams instead")]
        public virtual BigInteger[] V1
        {
            get { return new BigInteger[] { m_splitParams.V1A, m_splitParams.V1B }; }
        }

        [Obsolete("Access via SplitParams instead")]
        public virtual BigInteger[] V2
        {
            get { return new BigInteger[] { m_splitParams.V2A, m_splitParams.V2B }; }
        }

        [Obsolete("Access via SplitParams instead")]
        public virtual BigInteger G1
        {
            get { return m_splitParams.G1; }
        }

        [Obsolete("Access via SplitParams instead")]
        public virtual BigInteger G2
        {
            get { return m_splitParams.G2; }
        }

        [Obsolete("Access via SplitParams instead")]
        public virtual int Bits
        {
            get { return m_splitParams.Bits; }
        }
    }
}
