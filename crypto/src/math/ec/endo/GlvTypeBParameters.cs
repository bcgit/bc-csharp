using System;

namespace Org.BouncyCastle.Math.EC.Endo
{
    /// <summary>The parameters of the GLV endomorphism for curves of type B.</summary>
    public class GlvTypeBParameters
    {
        /// <summary>The lambda.</summary>
        protected readonly BigInteger m_beta, m_lambda;
        /// <summary>The split params.</summary>
        protected readonly ScalarSplitParameters m_splitParams;

        /// <summary>Create a new <see cref="GlvTypeBParameters"/>.</summary>
        /// <param name="beta">The beta.</param>
        /// <param name="lambda">The lambda.</param>
        /// <param name="splitParams">The split params.</param>
        public GlvTypeBParameters(BigInteger beta, BigInteger lambda, ScalarSplitParameters splitParams)
        {
            this.m_beta = beta;
            this.m_lambda = lambda;
            this.m_splitParams = splitParams;
        }

        /// <summary>Gets the beta.</summary>
        public virtual BigInteger Beta
        {
            get { return m_beta; }
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
