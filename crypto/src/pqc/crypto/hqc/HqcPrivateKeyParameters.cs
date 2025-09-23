using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.Hqc
{
    public sealed class HqcPrivateKeyParameters
        : HqcKeyParameters
    {
        private readonly byte[] m_sk;

        // TODO[api] Rename to 'parameters'
        public HqcPrivateKeyParameters(HqcParameters param, byte[] sk)
            : base(isPrivate: true, param)
        {
            m_sk = Arrays.CopyBuffer(sk);
        }

        public byte[] GetEncoded() => GetPrivateKey();

        public byte[] GetPrivateKey() => Arrays.CopyBuffer(m_sk);

        internal byte[] InternalPrivateKey => m_sk;

        [Obsolete("Use 'GetPrivateKey' instead")]
        public byte[] PrivateKey => GetPrivateKey();
    }
}
