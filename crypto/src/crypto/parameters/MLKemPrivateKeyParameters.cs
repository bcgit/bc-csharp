using System;
using System.Diagnostics;

using Org.BouncyCastle.Crypto.Kems.MLKem;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// An ML-KEM private (decapsulation) key, as specified in FIPS 203.
    /// </summary>
    /// <remarks>
    /// A private key may be stored in one of three equivalent forms, selected by <see cref="Format"/>: the
    /// 32-byte seed only, the expanded byte encoding only, or both. The seed form is the smallest and is
    /// preferred where the runtime can re-expand it on use; the expanded encoding avoids re-expansion but is
    /// much larger.
    /// </remarks>
    public sealed class MLKemPrivateKeyParameters
        : MLKemKeyParameters
    {
        /// <summary>Representation format for an ML-KEM private key.</summary>
        public enum Format
        {
            /// <summary>Store the 32-byte seed only; the expanded encoding is regenerated on demand.</summary>
            SeedOnly,
            /// <summary>Store the full expanded FIPS 203 private key encoding only (no seed available).</summary>
            EncodingOnly,
            /// <summary>Store both the seed and the expanded encoding.</summary>
            SeedAndEncoding
        };

        /// <summary>
        /// Create an <see cref="MLKemPrivateKeyParameters"/> from its expanded FIPS 203 private key encoding.
        /// </summary>
        /// <param name="parameters">The ML-KEM algorithm parameters this key belongs to.</param>
        /// <param name="encoding">The raw decapsulation key bytes. Length must equal the parameter set's
        /// <c>SecretKeyBytes</c>.</param>
        /// <returns>A private key in <see cref="Format.EncodingOnly"/> form (no seed retained).</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
        /// <paramref name="encoding"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="encoding"/> has the wrong length or fails the
        /// FIPS 203 hash check.</exception>
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

        /// <summary>
        /// Derive a private key from its 32-byte seed, defaulting to the <see cref="Format.SeedOnly"/>
        /// representation.
        /// </summary>
        /// <param name="parameters">The ML-KEM algorithm parameters.</param>
        /// <param name="seed">The 32-byte FIPS 203 seed <c>(d || z)</c>.</param>
        /// <returns>A new private key whose expanded encoding is derived from the seed.</returns>
        /// <exception cref="ArgumentNullException">If any argument is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="seed"/> has the wrong length.</exception>
        public static MLKemPrivateKeyParameters FromSeed(MLKemParameters parameters, byte[] seed) =>
            FromSeed(parameters, seed, preferredFormat: Format.SeedOnly);

        /// <summary>
        /// Derive a private key from its 32-byte seed, selecting the preferred on-disk representation.
        /// </summary>
        /// <param name="parameters">The ML-KEM algorithm parameters.</param>
        /// <param name="seed">The 32-byte FIPS 203 seed <c>(d || z)</c>.</param>
        /// <param name="preferredFormat">The format to report via <see cref="PreferredFormat"/>. Must be
        /// <see cref="Format.SeedOnly"/> or <see cref="Format.SeedAndEncoding"/> since a seed is available.</param>
        /// <returns>A new private key whose expanded encoding is derived from the seed.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
        /// <paramref name="seed"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="seed"/> has the wrong length or
        /// <paramref name="preferredFormat"/> is not valid.</exception>
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

        /// <summary>Returns a copy of the expanded FIPS 203 private key encoding.</summary>
        public byte[] GetEncoded() => Arrays.InternalCopyBuffer(m_encoding);

        /// <summary>Extracts the matching <see cref="MLKemPublicKeyParameters"/> from this private key.</summary>
        public MLKemPublicKeyParameters GetPublicKey() =>
            new MLKemPublicKeyParameters(Parameters, GetPublicKeyEncoded());

        /// <summary>Returns the raw public (encapsulation) key bytes embedded in this private key.</summary>
        public byte[] GetPublicKeyEncoded() => Parameters.ParameterSet.Engine.CopyEncapKey(decapKey: m_encoding);

        /// <summary>
        /// Returns a copy of the 32-byte seed, or <c>null</c> if the key was imported without one (i.e. created
        /// via <see cref="FromEncoding"/>).
        /// </summary>
        public byte[] GetSeed() => Arrays.Clone(m_seed);

        /// <summary>The caller-preferred encoding format (see <see cref="Format"/>).</summary>
        public Format PreferredFormat => m_preferredFormat;

        internal byte[] Seed => m_seed;

        /// <summary>
        /// Returns this key with a different <see cref="PreferredFormat"/>, or the same instance if no change
        /// is needed.
        /// </summary>
        /// <param name="preferredFormat">The new format. Requesting a seed-bearing format when no seed is
        /// available throws <see cref="InvalidOperationException"/>.</param>
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
