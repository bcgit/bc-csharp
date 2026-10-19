using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>A basic SRP Identity holder.</summary>
    public class BasicTlsSrpIdentity
        : TlsSrpIdentity
    {
        protected readonly byte[] m_identity;
        protected readonly byte[] m_password;

        /// <summary>Create a new <see cref="BasicTlsSrpIdentity"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="password">The password.</param>
        public BasicTlsSrpIdentity(byte[] identity, byte[] password)
        {
            this.m_identity = Arrays.Clone(identity);
            this.m_password = Arrays.Clone(password);
        }

        /// <summary>Create a new <see cref="BasicTlsSrpIdentity"/>.</summary>
        /// <param name="identity">The identity.</param>
        /// <param name="password">The password.</param>
        public BasicTlsSrpIdentity(string identity, string password)
        {
            this.m_identity = Strings.ToUtf8ByteArray(identity);
            this.m_password = Strings.ToUtf8ByteArray(password);
        }

        /// <inheritdoc/>
        public virtual byte[] GetSrpIdentity()
        {
            return m_identity;
        }

        /// <inheritdoc/>
        public virtual byte[] GetSrpPassword()
        {
            return m_password;
        }
    }
}
