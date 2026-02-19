namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for Key Derivation Functions for IEEE P1363a.</summary>
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

        public byte[] GetIV() => m_iv;

        public byte[] GetSharedSecret() => m_shared;
    }
}
