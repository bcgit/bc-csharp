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

            var engine = parameters.ParameterSet.Engine;

            if (encoding.Length != engine.SecretKeyBytes)
                throw new ArgumentException("Invalid length", nameof(encoding));

            encoding = Arrays.InternalCopyBuffer(encoding);

            if (!engine.CheckDecapKeyHash(encoding))
                throw new ArgumentException("Hash check failed", nameof(encoding));

            return new MLKemPrivateKeyParameters(parameters, seed: null, encoding, Format.EncodingOnly);
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
            if (seed.Length != MLKemEngine.SeedBytes)
                throw new ArgumentException("Invalid length", nameof(seed));

            preferredFormat = CheckFormat(preferredFormat, seed);

            seed = Arrays.InternalCopyBuffer(seed);

            parameters.ParameterSet.Engine.GenerateKemKeyPairInternal(seed, out byte[] encoding);

            return new MLKemPrivateKeyParameters(parameters, seed, encoding, preferredFormat);
        }

        private readonly byte[] m_seed;
        private readonly byte[] m_encoding;
        private readonly Format m_preferredFormat;

        internal MLKemPrivateKeyParameters(MLKemParameters parameters, byte[] seed, byte[] encoding,
            Format preferredFormat)
            : base(isPrivate: true, parameters)
        {
            Debug.Assert(null != seed || Format.EncodingOnly == preferredFormat);

            m_seed = seed;
            m_encoding = encoding ?? throw new ArgumentNullException(nameof(encoding));
            m_preferredFormat = preferredFormat;
        }

        internal byte[] Encoding => m_encoding;

        public byte[] GetEncoded() => Arrays.InternalCopyBuffer(m_encoding);

        public MLKemPublicKeyParameters GetPublicKey() =>
            new MLKemPublicKeyParameters(Parameters, GetPublicKeyEncoded());

        public byte[] GetPublicKeyEncoded() => Parameters.ParameterSet.Engine.CopyEncapKey(decapKey: m_encoding);

        public byte[] GetSeed() => Arrays.Clone(m_seed);

        public Format PreferredFormat => m_preferredFormat;

        internal byte[] Seed => m_seed;

        public MLKemPrivateKeyParameters WithPreferredFormat(Format preferredFormat)
        {
            if (m_preferredFormat == preferredFormat)
                return this;

            return new MLKemPrivateKeyParameters(Parameters, m_seed, m_encoding, CheckFormat(preferredFormat, m_seed));
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
