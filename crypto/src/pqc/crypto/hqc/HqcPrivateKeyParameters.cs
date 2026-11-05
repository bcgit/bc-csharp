using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /// <summary>An HQC private (decapsulation) key, represented by its raw byte encoding.</summary>
    /// <remarks>
    /// The encoding is dkKEM = seedKEM, the 32-byte seed from which the HQC specification of 2026-10-12 derives the
    /// whole key pair (Section 3.7, Table 9). The expanded form decapsulation works on - ekPKE, seedPKE.dk and sigma -
    /// is derived from it on first use and kept, the caching the specification allows to offset the cost of
    /// re-deriving it on every decapsulation.
    /// </remarks>
    public sealed class HqcPrivateKeyParameters
        : HqcKeyParameters
    {
        private readonly byte[] m_seed;

        private byte[] m_expanded;

        /// <summary>Creates an HQC private key from its raw encoding.</summary>
        /// <param name="param">The HQC parameter set this key belongs to.</param>
        /// <param name="sk">The 32-byte seedKEM; a defensive copy is taken.</param>
        /// <exception cref="ArgumentException">If <paramref name="sk"/> is not 32 bytes long.</exception>
        // TODO[api] Rename to 'parameters'
        public HqcPrivateKeyParameters(HqcParameters param, byte[] sk)
            : base(isPrivate: true, param)
        {
            if (sk == null)
                throw new ArgumentNullException(nameof(sk));
            if (sk.Length != HqcEngine.SeedBytes)
                throw new ArgumentException("'sk' has invalid length", nameof(sk));

            m_seed = Arrays.CopyBuffer(sk);
        }

        // Takes ownership of 'seed' and 'expanded'; no copies are made.
        internal HqcPrivateKeyParameters(HqcParameters parameters, byte[] seed, byte[] expanded)
            : base(isPrivate: true, parameters)
        {
            m_seed = seed;
            m_expanded = expanded;
        }

        /// <summary>Returns a copy of the raw private key encoding, the 32-byte seedKEM.</summary>
        public byte[] GetEncoded() => GetPrivateKey();

        /// <summary>Returns a copy of the raw private key bytes, the 32-byte seedKEM.</summary>
        public byte[] GetPrivateKey() => Arrays.CopyBuffer(m_seed);

        /// <summary>Returns the encapsulation key this decapsulation key pairs with, derived from the seed.</summary>
        public HqcPublicKeyParameters GetPublicKeyParameters() =>
            new HqcPublicKeyParameters(Parameters, Arrays.CopySegment(GetExpandedKey(), 0, Parameters.PublicKeyBytes));

        /// <summary>
        /// The expanded key ekPKE || seedPKE.dk || sigma, derived on first call and cached. Callers read it in place
        /// and must not modify it.
        /// </summary>
        internal byte[] GetExpandedKey() => Objects.EnsureSingletonInitialized(ref m_expanded, this,
            key => key.Parameters.Engine.ExpandSecretKey(key.m_seed));

        /// <summary>Obsolete. Use <see cref="GetPrivateKey"/> instead.</summary>
        [Obsolete("Use 'GetPrivateKey' instead")]
        public byte[] PrivateKey => GetPrivateKey();
    }
}
