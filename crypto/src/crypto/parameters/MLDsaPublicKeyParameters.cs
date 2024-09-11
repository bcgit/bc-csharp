using System;

using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaPublicKeyParameters
        : MLDsaKeyParameters
    {
        internal readonly byte[] m_rho;
        internal readonly byte[] m_t1;

        public MLDsaPublicKeyParameters(MLDsaParameters parameters, byte[] encoding)
            : base(false, parameters)
        {
            // TODO Validation

            m_rho = Arrays.CopyOfRange(encoding, 0, DilithiumEngine.SeedBytes);
            m_t1 = Arrays.CopyOfRange(encoding, DilithiumEngine.SeedBytes, encoding.Length);
        }

        internal MLDsaPublicKeyParameters(MLDsaParameters parameters, byte[] rho, byte[] t1)
            : base(false, parameters)
        {
            // TODO Validation

            m_rho = Arrays.Clone(rho);
            m_t1 = Arrays.Clone(t1);
        }

        public byte[] GetEncoded() => Arrays.Concatenate(m_rho, m_t1);

        internal bool VerifyInternal(byte[] msg, int msgOff, int msgLen, byte[] sig)
        {
            var engine = Parameters.GetEngine(null);

            return engine.Verify(sig, sig.Length, msg, msgOff, msgLen, m_rho, encT1: m_t1);
        }
    }
}
