using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public sealed class MLKemPrivateKeyParameters
        : MLKemKeyParameters
    {
        public enum Format { SeedOnly, EncodingOnly, SeedAndEncoding };

        public static MLKemPrivateKeyParameters FromEncoding(MLKemParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PrivateKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            var engine = parameters.ParameterSet.GetEngine(random: null);

            int index = 0;

            byte[] s = Arrays.CopyOfRange(encoding, 0, engine.IndCpaSecretKeyBytes);
            index += engine.IndCpaSecretKeyBytes;

            byte[] t = Arrays.CopyOfRange(encoding, index, index + engine.IndCpaPublicKeyBytes - MLKemEngine.SymBytes);
            index += engine.IndCpaPublicKeyBytes - MLKemEngine.SymBytes;

            byte[] rho = Arrays.CopyOfRange(encoding, index, index + 32);
            index += 32;

            byte[] hpk = Arrays.CopyOfRange(encoding, index, index + 32);
            index += 32;

            byte[] nonce = Arrays.CopyOfRange(encoding, index, index + MLKemEngine.SymBytes);
            //index += MLKemEngine.SymBytes;

            byte[] seed = null;

            return new MLKemPrivateKeyParameters(parameters, s, hpk, nonce, t, rho, seed, Format.EncodingOnly);
        }

        public static MLKemPrivateKeyParameters FromSeed(MLKemParameters parameters, byte[] seed) =>
            FromSeed(parameters, seed, preferredFormat: Format.SeedOnly);

        public static MLKemPrivateKeyParameters FromSeed(MLKemParameters parameters, byte[] seed,
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

            byte[] d = Arrays.CopyOfRange(seed, 0, MLKemEngine.SymBytes);
            byte[] z = Arrays.CopyOfRange(seed, MLKemEngine.SymBytes, seed.Length);

            engine.GenerateKemKeyPairInternal(d, z, out byte[] t, out byte[] rho, out byte[] s, out byte[] hpk,
                out byte[] nonce, out byte[] seed2);

            return new MLKemPrivateKeyParameters(parameters, s, hpk, nonce, t, rho, seed2, format);
        }

        internal readonly byte[] m_s;
        internal readonly byte[] m_hpk;
        internal readonly byte[] m_nonce;
        internal readonly byte[] m_t;
        internal readonly byte[] m_rho;
        internal readonly byte[] m_seed;

        private readonly Format m_preferredFormat;

        internal MLKemPrivateKeyParameters(MLKemParameters parameters, byte[] s, byte[] hpk, byte[] nonce, byte[] t,
            byte[] rho, byte[] seed, Format preferredFormat)
            : base(true, parameters)
        {
            Debug.Assert(null != seed || Format.EncodingOnly == preferredFormat);

            m_s = s;
            m_hpk = hpk;
            m_nonce = nonce;
            m_t = t;
            m_rho = rho;
            m_seed = seed;
            m_preferredFormat = preferredFormat;
        }

        public byte[] GetEncoded() => Arrays.ConcatenateAll(m_s, m_t, m_rho, m_hpk, m_nonce);

        public MLKemPublicKeyParameters GetPublicKey() => new MLKemPublicKeyParameters(Parameters, m_t, m_rho);

        public byte[] GetPublicKeyEncoded() => Arrays.Concatenate(m_t, m_rho);

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        public Format PreferredFormat => m_preferredFormat;

        internal byte[] Seed => m_seed;

        public MLKemPrivateKeyParameters WithPreferredFormat(Format preferredFormat)
        {
            if (m_preferredFormat == preferredFormat)
                return this;

            return new MLKemPrivateKeyParameters(Parameters, m_seed, m_hpk, m_nonce, m_t, m_rho, m_seed,
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
