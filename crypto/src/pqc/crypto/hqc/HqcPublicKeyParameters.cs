using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcPublicKeyParameters
        : HqcKeyParameters
    {
        private readonly byte[] m_pk;

        // TODO[api] Rename to 'parameters'
        public HqcPublicKeyParameters(HqcParameters param, byte[] pk)
            : base(isPrivate: false, param)
        {
            m_pk = Arrays.CopyBuffer(pk);
        }

        public byte[] GetEncoded() => GetPublicKey();

        public byte[] GetPublicKey() => Arrays.CopyBuffer(m_pk);

        internal byte[] InternalPublicKey => m_pk;

        [Obsolete("Use 'GetPublicKey' instead")]
        public byte[] PublicKey => GetPublicKey();
    }
}
