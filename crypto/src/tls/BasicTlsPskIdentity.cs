using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A basic PSK Identity holder.</summary>
    public class BasicTlsPskIdentity
        : TlsPskIdentity
    {
        /// <summary>The identity.</summary>
        protected readonly byte[] m_identity;
        /// <summary>The psk.</summary>
        protected readonly byte[] m_psk;

        /// <summary>Create a new <see cref="BasicTlsPskIdentity"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="psk">The psk.</param>
        public BasicTlsPskIdentity(byte[] identity, byte[] psk)
        {
            this.m_identity = Arrays.Clone(identity);
            this.m_psk = Arrays.Clone(psk);
        }

        /// <summary>Create a new <see cref="BasicTlsPskIdentity"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="psk">The psk.</param>
        public BasicTlsPskIdentity(string identity, byte[] psk)
        {
            this.m_identity = Strings.ToUtf8ByteArray(identity);
            this.m_psk = Arrays.Clone(psk);
        }

        /// <inheritdoc/>
        public virtual void SkipIdentityHint()
        {
        }

        /// <inheritdoc/>
        public virtual void NotifyIdentityHint(byte[] psk_identity_hint)
        {
        }

        /// <inheritdoc/>
        public virtual byte[] GetPskIdentity()
        {
            return m_identity;
        }

        /// <inheritdoc/>
        public byte[] GetPsk()
        {
            return Arrays.Clone(m_psk);
        }
    }
}
