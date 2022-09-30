using System;
using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Crypto.Parameters
{
    /**
     * parameters for Key derivation functions for IEEE P1363a
     */
    public class KdfParameters
        : IDerivationParameters
    {
        private readonly byte[] m_iv;
        private readonly byte[] m_shared;

        public KdfParameters(byte[] shared, byte[] iv)
        {
            m_shared = shared;
            m_iv = iv;
        }

        public byte[] GetSharedSecret()
        {
            return m_shared;
        }

        public byte[] GetIV()
        {
            return m_iv;
        }
    }
}
