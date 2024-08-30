using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaPrivateKeyParameters
        : MLDsaKeyParameters
    {
        internal byte[] m_rho;
        internal byte[] m_k;
        internal byte[] m_tr;
        internal byte[] m_s1;
        internal byte[] m_s2;
        internal byte[] m_t0;

        public MLDsaPrivateKeyParameters(MLDsaParameters parameters, byte[] encoding)
            : base(true, parameters)
        {
            // TODO Validation

            var engine = parameters.GetEngine(null);

            int index = 0;
            m_rho = Arrays.CopyOfRange(encoding, 0, DilithiumEngine.SeedBytes); index += DilithiumEngine.SeedBytes;
            m_k = Arrays.CopyOfRange(encoding, index, index + DilithiumEngine.SeedBytes); index += DilithiumEngine.SeedBytes;
            m_tr = Arrays.CopyOfRange(encoding, index, index + DilithiumEngine.TrBytes); index += DilithiumEngine.TrBytes;
            int delta = engine.L * engine.PolyEtaPackedBytes;
            m_s1 = Arrays.CopyOfRange(encoding, index, index + delta); index += delta;
            delta = engine.K * engine.PolyEtaPackedBytes;
            m_s2 = Arrays.CopyOfRange(encoding, index, index + delta); index += delta;
            delta = engine.K * DilithiumEngine.PolyT0PackedBytes;
            m_t0 = Arrays.CopyOfRange(encoding, index, index + delta);
        }

        internal MLDsaPrivateKeyParameters(MLDsaParameters parameters, byte[] rho, byte[] K, byte[] tr, byte[] s1,
            byte[] s2, byte[] t0, byte[] t1)
            : base(true, parameters)
        {
            // TODO Validation

            m_rho = Arrays.Clone(rho);
            m_k = Arrays.Clone(K);
            m_tr = Arrays.Clone(tr);
            m_s1 = Arrays.Clone(s1);
            m_s2 = Arrays.Clone(s2);
            m_t0 = Arrays.Clone(t0);
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_rho, m_k, m_tr, m_s1, m_s2, m_t0);

        internal byte[] SignInternal(byte[] rnd, byte[] msg, int msgOff, int msgLen)
        {
            var engine = Parameters.GetEngine(null);

            byte[] sig = new byte[engine.CryptoBytes];
            engine.SignInternal(sig, sig.Length, msg, msgOff, msgLen, m_rho, m_k, m_tr, m_t0, m_s1, m_s2, rnd,
                legacy: false);
            return sig;
        }
    }
}
