using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>
    /// A basic implementation of <see cref="TlsPskExternal"/>, an externally established pre-shared key.
    /// </summary>
    public class BasicTlsPskExternal
        : TlsPskExternal
    {
        protected readonly byte[] m_identity;
        protected readonly TlsSecret m_key;
        protected readonly int m_prfAlgorithm;

        /// <summary>Create a new <see cref="BasicTlsPskExternal"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="key">The key.</param>
        public BasicTlsPskExternal(byte[] identity, TlsSecret key)
            : this(identity, key, Tls.PrfAlgorithm.tls13_hkdf_sha256)
        {
        }

        /// <summary>Create a new <see cref="BasicTlsPskExternal"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="key">The key.</param>
        /// <param name="prfAlgorithm">The prf algorithm.</param>
        public BasicTlsPskExternal(byte[] identity, TlsSecret key, int prfAlgorithm)
        {
            m_identity = Arrays.Clone(identity);
            m_key = key;
            m_prfAlgorithm = prfAlgorithm;
        }

        /// <inheritdoc/>
        public virtual byte[] Identity => m_identity;

        /// <inheritdoc/>
        public virtual TlsSecret Key => m_key;

        /// <inheritdoc/>
        public virtual int PrfAlgorithm => m_prfAlgorithm;
    }
}
