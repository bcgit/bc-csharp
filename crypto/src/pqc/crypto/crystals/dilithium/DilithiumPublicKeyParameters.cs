using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium
{
    [Obsolete("Use ML-DSA instead")]
    public sealed class DilithiumPublicKeyParameters
        : DilithiumKeyParameters
    {
        internal static byte[] GetEncoded(byte[] rho, byte[] t1) => Arrays.Concatenate(rho, t1);

        internal readonly byte[] m_rho;
        internal readonly byte[] m_t1;

        public DilithiumPublicKeyParameters(DilithiumParameters parameters, byte[] rho, byte[] t1)
            : base(false, parameters)
        {
            m_rho = Arrays.Clone(rho);
            m_t1 = Arrays.Clone(t1);
        }

        public DilithiumPublicKeyParameters(DilithiumParameters parameters, byte[] pkEncoded)
            : base(false, parameters)
        {
            m_rho = Arrays.CopyOfRange(pkEncoded, 0, DilithiumEngine.SeedBytes);
            m_t1 = Arrays.CopyOfRange(pkEncoded, DilithiumEngine.SeedBytes, pkEncoded.Length);
        }

        public byte[] GetEncoded() => GetEncoded(m_rho, m_t1);

        public byte[] GetRho() => Arrays.Clone(m_rho);

        public byte[] GetT1() => Arrays.Clone(m_t1);
    }
}
