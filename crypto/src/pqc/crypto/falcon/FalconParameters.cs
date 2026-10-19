using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    public sealed class FalconParameters
        : ICipherParameters
    {
        public static readonly FalconParameters falcon_512 = new FalconParameters("falcon512", 9, 40);
        public static readonly FalconParameters falcon_1024 = new FalconParameters("falcon1024", 10, 40);

        private readonly string m_name;
        private readonly int m_logN;
        private readonly int m_nonceLength;

        private FalconParameters(string name, int logn, int nonceLength)
        {
            m_name = name;
            m_logN = logn;
            m_nonceLength = nonceLength;
        }

        /// <summary>Gets the log n.</summary>
        public int LogN => m_logN;

        /// <summary>Gets the nonce length.</summary>
        public int NonceLength => m_nonceLength;

        /// <summary>Gets the name.</summary>
        public string Name => m_name;

        /// <inheritdoc/>
        public override string ToString() => Name;
    }
}
