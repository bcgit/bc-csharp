using System;

namespace Org.BouncyCastle.Tls.Crypto
{
    /// <summary>Basic config for Diffie-Hellman.</summary>
    public class TlsDHConfig
    {
        protected readonly DHGroup m_explicitGroup;
        protected readonly int m_namedGroup;
        protected readonly bool m_padded;

        /// <summary>Create a new <see cref="TlsDHConfig"/>.</summary>
        /// <param name="explicitGroup">The explicit group.</param>
        public TlsDHConfig(DHGroup explicitGroup)
        {
            this.m_explicitGroup = explicitGroup;
            this.m_namedGroup = -1;
            this.m_padded = false;
        }

        /// <summary>Create a new <see cref="TlsDHConfig"/>.</summary>
        /// <param name="namedGroup">The named group.</param>
        /// <param name="padded">true if padded, false otherwise.</param>
        public TlsDHConfig(int namedGroup, bool padded)
        {
            this.m_explicitGroup = null;
            this.m_namedGroup = namedGroup;
            this.m_padded = padded;
        }

        /// <summary>Gets the explicit group.</summary>
        public virtual DHGroup ExplicitGroup
        {
            get { return m_explicitGroup; }
        }

        /// <summary>Gets the named group.</summary>
        public virtual int NamedGroup
        {
            get { return m_namedGroup; }
        }

        /// <summary>Gets a value indicating whether this is padded.</summary>
        public virtual bool IsPadded
        {
            get { return m_padded; }
        }
    }
}
