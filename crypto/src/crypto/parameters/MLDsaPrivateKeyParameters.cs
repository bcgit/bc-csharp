using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Signers.MLDsa;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLDsaPrivateKeyParameters
        : MLDsaKeyParameters
    {
        public enum Format { SeedOnly, EncodingOnly, SeedAndEncoding };

        public static MLDsaPrivateKeyParameters FromEncoding(MLDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            var engine = parameters.ParameterSet.GetEngine(random: null);

            int index = 0;

            byte[] rho = Arrays.CopyOfRange(encoding, 0, MLDsaEngine.SeedBytes);
            index += MLDsaEngine.SeedBytes;

            byte[] k = Arrays.CopyOfRange(encoding, index, index + MLDsaEngine.SeedBytes);
            index += MLDsaEngine.SeedBytes;

            byte[] tr = Arrays.CopyOfRange(encoding, index, index + MLDsaEngine.TrBytes);
            index += MLDsaEngine.TrBytes;

            int delta = engine.L * engine.PolyEtaPackedBytes;
            byte[] s1 = Arrays.CopyOfRange(encoding, index, index + delta);
            index += delta;

            delta = engine.K * engine.PolyEtaPackedBytes;
            byte[] s2 = Arrays.CopyOfRange(encoding, index, index + delta);
            index += delta;

            delta = engine.K * MLDsaEngine.PolyT0PackedBytes;
            byte[] t0 = Arrays.CopyOfRange(encoding, index, index + delta);
            //index += delta;

            byte[] t1 = engine.DeriveT1(rho, s1, s2, t0);
            byte[] seed = null;

            return new MLDsaPrivateKeyParameters(parameters, rho, k, tr, s1, s2, t0, t1, seed, Format.EncodingOnly);
        }

        public static MLDsaPrivateKeyParameters FromSeed(MLDsaParameters parameters, byte[] seed) =>
            FromSeed(parameters, seed, preferredFormat: Format.SeedOnly);

        public static MLDsaPrivateKeyParameters FromSeed(MLDsaParameters parameters, byte[] seed,
            Format preferredFormat)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (seed == null)
                throw new ArgumentNullException(nameof(seed));
            if (seed.Length != parameters.ParameterSet.SeedLength)
                throw new ArgumentException("invalid seed", nameof(seed));

            var format = CheckFormat(preferredFormat, seed);

            var engine = parameters.ParameterSet.GetEngine(random: null);

            engine.GenerateKeyPairInternal(seed, out var rho, out var k, out var tr, out var s1, out var s2, out var t0,
                out var t1);

            return new MLDsaPrivateKeyParameters(parameters, rho, k, tr, s1, s2, t0, t1, seed, format);
        }

        internal readonly byte[] m_rho;
        internal readonly byte[] m_k;
        internal readonly byte[] m_tr;
        internal readonly byte[] m_s1;
        internal readonly byte[] m_s2;
        internal readonly byte[] m_t0;
        internal readonly byte[] m_t1;
        internal readonly byte[] m_seed;

        private readonly Format m_preferredFormat;

        internal MLDsaPrivateKeyParameters(MLDsaParameters parameters, byte[] rho, byte[] k, byte[] tr, byte[] s1,
            byte[] s2, byte[] t0, byte[] t1, byte[] seed, Format preferredFormat)
            : base(true, parameters)
        {
            Debug.Assert(null != seed || Format.EncodingOnly == preferredFormat);

            m_rho = rho;
            m_k = k;
            m_tr = tr;
            m_s1 = s1;
            m_s2 = s2;
            m_t0 = t0;
            m_t1 = t1;
            m_seed = seed;
            m_preferredFormat = preferredFormat;
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_rho, m_k, m_tr, m_s1, m_s2, m_t0);

        public MLDsaPublicKeyParameters GetPublicKey() => new MLDsaPublicKeyParameters(Parameters, m_rho, m_t1);

        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_rho, m_t1);

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        public Format PreferredFormat => m_preferredFormat;

        internal byte[] Seed => m_seed;

        // NB: Don't remove - needed by commented-out test cases
        internal byte[] SignInternal(byte[] rnd, byte[] msg, int msgOff, int msgLen)
        {
            var engine = Parameters.ParameterSet.GetEngine(random: null);

            byte[] sig = new byte[engine.CryptoBytes];
            engine.SignInternal(sig, sig.Length, msg, msgOff, msgLen, m_rho, m_k, m_tr, m_t0, m_s1, m_s2, rnd);
            return sig;
        }

        public MLDsaPrivateKeyParameters WithPreferredFormat(Format preferredFormat)
        {
            if (m_preferredFormat == preferredFormat)
                return this;

            return new MLDsaPrivateKeyParameters(Parameters, m_rho, m_k, m_tr, m_s1, m_s2, m_t0, m_t1, m_seed,
                CheckFormat(preferredFormat, m_seed));
        }

        private static Format CheckFormat(Format preferredFormat, byte[] seed)
        {
            switch (preferredFormat)
            {
            case Format.EncodingOnly:
                break;
            case Format.SeedAndEncoding:
            case Format.SeedOnly:
            {
                if (seed == null)
                    throw new InvalidOperationException("no seed available");

                break;
            }
            default:
                throw new ArgumentException("invalid format", nameof(preferredFormat));
            }

            return preferredFormat;
        }
    }
}
