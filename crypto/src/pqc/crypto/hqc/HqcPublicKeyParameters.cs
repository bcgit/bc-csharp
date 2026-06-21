using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    /// <summary>An HQC public (encapsulation) key, represented by its raw byte encoding.</summary>
    public sealed class HqcPublicKeyParameters
        : HqcKeyParameters
    {
        private readonly byte[] m_pk;

        /// <summary>Creates an HQC public key from its raw encoding.</summary>
        /// <param name="param">The HQC parameter set this key belongs to.</param>
        /// <param name="pk">The raw public key bytes; a defensive copy is taken.</param>
        // TODO[api] Rename to 'parameters'
        public HqcPublicKeyParameters(HqcParameters param, byte[] pk)
            : base(isPrivate: false, param)
        {
            m_pk = Arrays.CopyBuffer(pk);
        }

        /// <summary>Returns a copy of the raw public key encoding.</summary>
        public byte[] GetEncoded() => GetPublicKey();

        /// <summary>Returns a copy of the raw public key bytes.</summary>
        public byte[] GetPublicKey() => Arrays.CopyBuffer(m_pk);

        internal byte[] InternalPublicKey => m_pk;

        /// <summary>Obsolete. Use <see cref="GetPublicKey"/> instead.</summary>
        [Obsolete("Use 'GetPublicKey' instead")]
        public byte[] PublicKey => GetPublicKey();
    }
}
