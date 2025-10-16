namespace Org.BouncyCastle.Crypto
{
    public abstract class AsymmetricKeyParameter
        : ICipherParameters
    {
        private readonly bool m_privateKey;

        protected AsymmetricKeyParameter(bool privateKey)
        {
            m_privateKey = privateKey;
        }

        public bool IsPrivate => m_privateKey;

        public override bool Equals(object obj) => obj is AsymmetricKeyParameter that && Equals(that);

        protected bool Equals(AsymmetricKeyParameter other) => m_privateKey == other.m_privateKey;

        public override int GetHashCode() => m_privateKey.GetHashCode();
    }
}
