using System;

using Org.BouncyCastle.Crypto.Signers.MLDsa;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>
    /// An ML-DSA public (verification) key, as specified in FIPS 204.
    /// </summary>
    /// <remarks>
    /// Internally the key is kept split into the <c>rho</c> seed and the <c>t1</c> vector per FIPS 204 §5.2.
    /// The full public-key hash <c>tr</c> is computed lazily on first use and cached for subsequent verify
    /// operations.
    /// </remarks>
    public sealed class MLDsaPublicKeyParameters
        : MLDsaKeyParameters
    {
        /// <summary>
        /// Create an <see cref="MLDsaPublicKeyParameters"/> from its raw FIPS 204 public key encoding.
        /// </summary>
        /// <param name="parameters">The ML-DSA algorithm parameters this key belongs to.</param>
        /// <param name="encoding">The raw public key bytes. Length must equal the parameter set's
        /// <c>PublicKeyLength</c>.</param>
        /// <returns>A new <see cref="MLDsaPublicKeyParameters"/>.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="parameters"/> or
        /// <paramref name="encoding"/> is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">If <paramref name="encoding"/> has the wrong length.</exception>
        public static MLDsaPublicKeyParameters FromEncoding(MLDsaParameters parameters, byte[] encoding)
        {
            if (parameters == null)
                throw new ArgumentNullException(nameof(parameters));
            if (encoding == null)
                throw new ArgumentNullException(nameof(encoding));
            if (encoding.Length != parameters.ParameterSet.PublicKeyLength)
                throw new ArgumentException("invalid encoding", nameof(encoding));

            byte[] rho = Arrays.CopyOfRange(encoding, 0, MLDsaEngine.SeedBytes);
            byte[] t1 = Arrays.CopyOfRange(encoding, MLDsaEngine.SeedBytes, encoding.Length);
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

        /// <summary>Returns a fresh copy of the FIPS 204 public key encoding (<c>rho || t1</c>).</summary>
        public byte[] GetEncoded() => Arrays.Concatenate(m_rho, m_t1);

        internal byte[] GetPublicKeyHash() =>
            Objects.EnsureSingletonInitialized(ref cachedPublicKeyHash, this, CreatePublicKeyHash);

        // NB: Don't remove - needed by commented-out test cases
        internal bool VerifyInternal(byte[] msg, int msgOff, int msgLen, byte[] sig)
        {
            var engine = Parameters.ParameterSet.GetEngine(random: null);

            return engine.VerifyInternal(sig, sig.Length, msg, msgOff, msgLen, m_rho, encT1: m_t1,
                tr: GetPublicKeyHash());
        }

        private static byte[] CreatePublicKeyHash(MLDsaPublicKeyParameters publicKey) =>
            MLDsaEngine.CalculatePublicKeyHash(publicKey.m_rho, publicKey.m_t1);
    }
}
