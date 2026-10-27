using System;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A combined hash, which implements md5(m) || sha1(m).</summary>
    public class CombinedHash
        : TlsHash
    {
        /// <summary>The context.</summary>
        protected readonly TlsContext m_context;
        /// <summary>The crypto.</summary>
        protected readonly TlsCrypto m_crypto;
        /// <summary>The md 5.</summary>
        protected readonly TlsHash m_md5;
        /// <summary>The sha 1.</summary>
        protected readonly TlsHash m_sha1;

        internal CombinedHash(TlsContext context, TlsHash md5, TlsHash sha1)
        {
            this.m_context = context;
            this.m_crypto = context.Crypto;
            this.m_md5 = md5;
            this.m_sha1 = sha1;
        }

        /// <summary>Create a new <see cref="CombinedHash"/>.</summary>
        /// <param name="crypto">The crypto.</param>
        public CombinedHash(TlsCrypto crypto)
        {
            this.m_crypto = crypto;
            this.m_md5 = crypto.CreateHash(CryptoHashAlgorithm.md5);
            this.m_sha1 = crypto.CreateHash(CryptoHashAlgorithm.sha1);
        }

        /// <summary>Create a copy of the given <see cref="CombinedHash"/>.</summary>
        /// <param name="t">The instance to copy.</param>
        public CombinedHash(CombinedHash t)
        {
            this.m_context = t.m_context;
            this.m_crypto = t.m_crypto;
            this.m_md5 = t.m_md5.CloneHash();
            this.m_sha1 = t.m_sha1.CloneHash();
        }

        /// <inheritdoc/>
        public virtual void Update(byte[] input, int inOff, int len)
        {
            m_md5.Update(input, inOff, len);
            m_sha1.Update(input, inOff, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <inheritdoc/>
        public void Update(ReadOnlySpan<byte> input)
        {
            m_md5.Update(input);
            m_sha1.Update(input);
        }
#endif

        /// <inheritdoc/>
        public virtual byte[] CalculateHash()
        {
            if (null != m_context && TlsUtilities.IsSsl(m_context))
            {
                Ssl3Utilities.CompleteCombinedHash(m_context, m_md5, m_sha1);
            }

            return Arrays.Concatenate(m_md5.CalculateHash(), m_sha1.CalculateHash());
        }

        /// <inheritdoc/>
        public virtual TlsHash CloneHash()
        {
            return new CombinedHash(this);
        }

        /// <inheritdoc/>
        public virtual void Reset()
        {
            m_md5.Reset();
            m_sha1.Reset();
        }
    }
}
