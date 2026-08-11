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

        public int LogN => m_logN;

        public int NonceLength => m_nonceLength;

        public string Name => m_name;

        public override string ToString() => Name;
    }
}
