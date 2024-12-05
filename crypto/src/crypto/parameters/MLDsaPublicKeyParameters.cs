using System;

using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaPublicKeyParameters
        : MLDsaKeyParameters
    {
        public static MLDsaPublicKeyParameters FromEncoding(MLDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PublicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            byte[] rho = Arrays.CopyOfRange(encoding, 0, DilithiumEngine.SeedBytes);
            byte[] t1 = Arrays.CopyOfRange(encoding, DilithiumEngine.SeedBytes, encoding.Length);
            return new MLDsaPublicKeyParameters(parameters, rho, t1);
        }

        internal readonly byte[] m_rho;
        internal readonly byte[] m_t1;

        private byte[] cachedPublicKeyHash;

        internal MLDsaPublicKeyParameters(MLDsaParameters parameters, byte[] rho, byte[] t1)
            : base(false, parameters)
        {
            m_rho = rho;
            m_t1 = t1;
        }

        public byte[] GetEncoded() => Arrays.Concatenate(m_rho, m_t1);

        internal byte[] GetPublicKeyHash() =>
            Objects.EnsureSingletonInitialized(ref cachedPublicKeyHash, this, CreatePublicKeyHash);

        internal bool VerifyInternal(byte[] msg, int msgOff, int msgLen, byte[] sig)
        {
            var engine = Parameters.ParameterSet.GetEngine(random: null);

            return engine.VerifyInternal(sig, sig.Length, msg, msgOff, msgLen, m_rho, encT1: m_t1,
                tr: GetPublicKeyHash());
        }

        private static byte[] CreatePublicKeyHash(MLDsaPublicKeyParameters publicKey) =>
            DilithiumEngine.CalculatePublicKeyHash(publicKey.m_rho, publicKey.m_t1);
    }
}
