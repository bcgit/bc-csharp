namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Parameters for using an integrated cipher in stream mode.</summary>
    public class IesParameters
        : ICipherParameters
    {
        private readonly byte[] m_derivation;
        private readonly byte[] m_encoding;
        private readonly int m_macKeySize;

        /// <param name="derivation">the derivation parameter for the KDF function.</param>
        /// <param name="encoding">the encoding parameter for the KDF function.</param>
        /// <param name="macKeySize">the size of the MAC key (in bits).</param>
        public IesParameters(byte[] derivation, byte[] encoding, int macKeySize)
        {
            m_derivation = derivation;
            m_encoding = encoding;
            m_macKeySize = macKeySize;
        }

        /// <summary>Return the derivation v.</summary>
        public byte[] GetDerivationV() => m_derivation;

        /// <summary>Return the encoding v.</summary>
        public byte[] GetEncodingV() => m_encoding;

        /// <summary>Gets the mac key size.</summary>
        public int MacKeySize => m_macKeySize;
    }
}
