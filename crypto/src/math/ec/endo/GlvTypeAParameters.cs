using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    public class GlvTypeAParameters
    {
        /// <summary>The lambda.</summary>
        protected readonly BigInteger m_i, m_lambda;
        /// <summary>The split params.</summary>
        protected readonly ScalarSplitParameters m_splitParams;

        /// <summary>Create a new <see cref="GlvTypeAParameters"/>.</summary>
        /// <param name="i">The i.</param>
        /// <param name="lambda">The lambda.</param>
        /// <param name="splitParams">The split params.</param>
        public GlvTypeAParameters(BigInteger i, BigInteger lambda, ScalarSplitParameters splitParams)
        {
            this.m_i = i;
            this.m_lambda = lambda;
            this.m_splitParams = splitParams;
        }

        /// <summary>Gets the i.</summary>
        public virtual BigInteger I
        {
            get { return m_i; }
        }

        /// <summary>Gets the lambda.</summary>
        public virtual BigInteger Lambda
        {
            get { return m_lambda; }
        }

        /// <summary>Gets the split params.</summary>
        public virtual ScalarSplitParameters SplitParams
        {
            get { return m_splitParams; }
        }
    }
}
