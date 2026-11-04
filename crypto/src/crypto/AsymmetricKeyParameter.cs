namespace Org.BouncyCastle.Crypto
{
    /// <summary>Base class for asymmetric (public or private) key parameters.</summary>
    public abstract class AsymmetricKeyParameter
        : ICipherParameters
    {
        private readonly bool m_privateKey;

        /// <summary>Create a new <see cref="AsymmetricKeyParameter"/>.</summary>
        /// <param name="privateKey">The private key.</param>
        protected AsymmetricKeyParameter(bool privateKey)
        {
            m_privateKey = privateKey;
        }

        /// <summary>Gets a value indicating whether this is private.</summary>
        public bool IsPrivate => m_privateKey;

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is AsymmetricKeyParameter that && Equals(that);

        /// <summary>Determine whether these parameters are equal to another instance.</summary>
        /// <param name="other">The instance to compare with.</param>
        /// <returns>true if the parameters are equal, false otherwise.</returns>
        protected bool Equals(AsymmetricKeyParameter other) => m_privateKey == other.m_privateKey;

        /// <inheritdoc/>
        public override int GetHashCode() => m_privateKey.GetHashCode();
    }
}
