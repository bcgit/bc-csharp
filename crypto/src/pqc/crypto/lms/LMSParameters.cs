namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LmsParameters
    {
        private readonly LMSigParameters m_lmSigParameters;
        private readonly LMOtsParameters m_lmOtsParameters;

        public LmsParameters(LMSigParameters lmSigParameters, LMOtsParameters lmOtsParameters)
        {
            m_lmSigParameters = lmSigParameters;
            m_lmOtsParameters = lmOtsParameters;
        }

        public LMSigParameters LMSigParameters => m_lmSigParameters;

        public LMOtsParameters LMOtsParameters => m_lmOtsParameters;
    }
}
