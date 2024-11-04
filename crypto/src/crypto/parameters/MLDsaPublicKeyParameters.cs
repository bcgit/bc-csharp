using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaPublicKeyParameters
        : MLDsaKeyParameters
    {
        internal readonly byte[] m_rho;
        internal readonly byte[] m_t1;

        private byte[] cachedPublicKeyHash;

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

        internal byte[] GetPublicKeyHash() =>
            Objects.EnsureSingletonInitialized(ref cachedPublicKeyHash, this, CreatePublicKeyHash);

        internal bool VerifyInternal(byte[] msg, int msgOff, int msgLen, byte[] sig)
        {
            var engine = Parameters.ParameterSet.GetEngine(null);

            return engine.Verify(sig, sig.Length, msg, msgOff, msgLen, m_rho, encT1: m_t1, tr: GetPublicKeyHash());
        }

        private static byte[] CreatePublicKeyHash(MLDsaPublicKeyParameters publicKey) =>
            DilithiumEngine.CalculatePublicKeyHash(publicKey.m_rho, publicKey.m_t1);
    }
}
