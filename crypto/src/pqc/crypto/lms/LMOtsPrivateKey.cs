using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Lms
{
    // TODO[api] Make internal
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
            byte[] C = new byte[m_parameters.N];

            SeedDerive derive = GetDerivationFunction();
            derive.J = LMOts.SEED_RANDOMISER_INDEX; // This value from reference impl.
            derive.DeriveSeed(false, C, 0);

            IDigest ctx = LmsUtilities.GetDigest(m_parameters);

            LmsUtilities.ByteArray(m_I, ctx);
            LmsUtilities.U32Str(m_q, ctx);
            LmsUtilities.U16Str((short)LMOts.D_MESG, ctx);
            LmsUtilities.ByteArray(C, ctx);

            return new LmsContext(this, sigParams, ctx, C, path);
        }

        public byte[] GetI() => Arrays.Clone(m_I);

        public byte[] GetMasterSecret() => Arrays.Clone(m_masterSecret);

        public LMOtsParameters Parameters => m_parameters;

        public int Q => m_q;

        internal SeedDerive GetDerivationFunction()
        {
            return new SeedDerive(m_I, m_masterSecret, LmsUtilities.GetDigest(m_parameters))
            {
                Q = m_q,
                J = 0,
            };
        }

        [Obsolete("Use 'GetI' instead")]
        public byte[] I => m_I;

        [Obsolete("Use 'GetMasterSecret' instead")]
        public byte[] MasterSecret => m_masterSecret;
    }
}
