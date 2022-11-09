using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    public sealed class LMOtsPrivateKey
    {
        private readonly LMOtsParameters m_parameters;
        private readonly byte[] m_I;
        private readonly int m_q;
        private readonly byte[] m_masterSecret;

        public LMOtsPrivateKey(LMOtsParameters parameters, byte[] i, int q, byte[] masterSecret)
        {
            m_parameters = parameters;
            m_I = i;
            m_q = q;
            m_masterSecret = masterSecret;
        }

        public LmsContext GetSignatureContext(LMSigParameters sigParams, byte[][] path)
        {
            byte[] C = new byte[LMOts.SEED_LEN];

            SeedDerive derive = GetDerivationFunction();
            derive.J = LMOts.SEED_RANDOMISER_INDEX; // This value from reference impl.
            derive.DeriveSeed(false, C, 0);

            IDigest ctx = DigestUtilities.GetDigest(m_parameters.DigestOid);

            LmsUtilities.ByteArray(m_I, ctx);
            LmsUtilities.U32Str(m_q, ctx);
            LmsUtilities.U16Str((short)LMOts.D_MESG, ctx);
            LmsUtilities.ByteArray(C, ctx);

            return new LmsContext(this, sigParams, ctx, C, path);
        }

        internal SeedDerive GetDerivationFunction()
        {
            return new SeedDerive(m_I, m_masterSecret, DigestUtilities.GetDigest(m_parameters.DigestOid))
            {
                Q = m_q,
                J = 0,
            };
        }

        public LMOtsParameters Parameters => m_parameters;

        // FIXME
        public byte[] I => m_I;

        public int Q => m_q;

        // FIXME
        public byte[] MasterSecret => m_masterSecret;
    }
}
