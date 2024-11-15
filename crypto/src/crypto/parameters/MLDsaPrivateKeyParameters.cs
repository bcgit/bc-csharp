using System;

using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaPrivateKeyParameters
        : MLDsaKeyParameters
    {
        public static MLDsaPrivateKeyParameters FromEncoding(MLDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            var engine = parameters.ParameterSet.GetEngine(null);

            int index = 0;
            byte[] rho = Arrays.CopyOfRange(encoding, 0, DilithiumEngine.SeedBytes); index += DilithiumEngine.SeedBytes;
            byte[] k = Arrays.CopyOfRange(encoding, index, index + DilithiumEngine.SeedBytes); index += DilithiumEngine.SeedBytes;
            byte[] tr = Arrays.CopyOfRange(encoding, index, index + DilithiumEngine.TrBytes); index += DilithiumEngine.TrBytes;
            int delta = engine.L * engine.PolyEtaPackedBytes;
            byte[] s1 = Arrays.CopyOfRange(encoding, index, index + delta); index += delta;
            delta = engine.K * engine.PolyEtaPackedBytes;
            byte[] s2 = Arrays.CopyOfRange(encoding, index, index + delta); index += delta;
            delta = engine.K * DilithiumEngine.PolyT0PackedBytes;
            byte[] t0 = Arrays.CopyOfRange(encoding, index, index + delta);
            byte[] t1 = engine.DeriveT1(rho, s1, s2, t0);
            byte[] seed = null;

            return new MLDsaPrivateKeyParameters(parameters, rho, k, tr, s1, s2, t0, t1, seed);
        }

        public static MLDsaPrivateKeyParameters FromSeed(MLDsaParameters parameters, byte[] seed)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (seed == null)
                throw new ArgumentNullException(nameof(seed));
            if (seed.Length != parameters.ParameterSet.SeedLength)
                throw new ArgumentException("invalid seed", nameof(seed));

            var engine = parameters.ParameterSet.GetEngine(null);

            engine.GenerateKeyPairInternal(seed, legacy: false, out var rho, out var k, out var tr, out var s1,
                out var s2, out var t0, out var t1);

            return new MLDsaPrivateKeyParameters(parameters, rho, k, tr, s1, s2, t0, t1, seed);
        }

        internal readonly byte[] m_rho;
        internal readonly byte[] m_k;
        internal readonly byte[] m_tr;
        internal readonly byte[] m_s1;
        internal readonly byte[] m_s2;
        internal readonly byte[] m_t0;
        internal readonly byte[] m_t1;
        internal readonly byte[] m_seed;

        internal MLDsaPrivateKeyParameters(MLDsaParameters parameters, byte[] rho, byte[] k, byte[] tr, byte[] s1,
            byte[] s2, byte[] t0, byte[] t1, byte[] seed)
            : base(true, parameters)
        {
            m_rho = rho;
            m_k = k;
            m_tr = tr;
            m_s1 = s1;
            m_s2 = s2;
            m_t0 = t0;
            m_t1 = t1;
            m_seed = seed;
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_rho, m_k, m_tr, m_s1, m_s2, m_t0);

        public MLDsaPublicKeyParameters GetPublicKey() => new MLDsaPublicKeyParameters(Parameters, m_rho, m_t1);

        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_rho, m_t1);

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        internal byte[] Seed => m_seed;

        internal byte[] SignInternal(byte[] rnd, byte[] msg, int msgOff, int msgLen)
        {
            var engine = Parameters.ParameterSet.GetEngine(null);

            byte[] sig = new byte[engine.CryptoBytes];
            engine.SignInternal(sig, sig.Length, msg, msgOff, msgLen, m_rho, m_k, m_tr, m_t0, m_s1, m_s2, rnd,
                legacy: false);
            return sig;
        }
    }
}
