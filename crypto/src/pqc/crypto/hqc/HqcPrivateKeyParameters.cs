using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /// <summary>An HQC private (decapsulation) key, represented by its raw byte encoding.</summary>
    public sealed class HqcPrivateKeyParameters
        : HqcKeyParameters
    {
        private readonly byte[] m_sk;

        /// <summary>Creates an HQC private key from its raw encoding.</summary>
        /// <param name="param">The HQC parameter set this key belongs to.</param>
        /// <param name="sk">The raw private key bytes; a defensive copy is taken.</param>
        // TODO[api] Rename to 'parameters'
        public HqcPrivateKeyParameters(HqcParameters param, byte[] sk)
            : base(isPrivate: true, param)
        {
            m_sk = Arrays.CopyBuffer(sk);
        }

        /// <summary>Returns a copy of the raw private key encoding.</summary>
        public byte[] GetEncoded() => GetPrivateKey();

        /// <summary>Returns a copy of the raw private key bytes.</summary>
        public byte[] GetPrivateKey() => Arrays.CopyBuffer(m_sk);

        internal byte[] InternalPrivateKey => m_sk;

        /// <summary>Obsolete. Use <see cref="GetPrivateKey"/> instead.</summary>
        [Obsolete("Use 'GetPrivateKey' instead")]
        public byte[] PrivateKey => GetPrivateKey();
    }
}
