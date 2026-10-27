using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls
{
    /// <summary>The parameters of a TLS session, stored so that the session can be resumed.</summary>
    public sealed class SessionParameters
    {
        /// <summary>A builder for <see cref="SessionParameters"/>.</summary>
        public sealed class Builder
        {
            private int m_cipherSuite = -1;
            private Certificate m_localCertificate = null;
            private TlsSecret m_masterSecret = null;
            private ProtocolVersion m_negotiatedVersion;
            private Certificate m_peerCertificate = null;
            private byte[] m_pskIdentity = null;
            private byte[] m_srpIdentity = null;
            private byte[] m_encodedServerExtensions = null;
            private bool m_extendedMasterSecret = false;

            /// <summary>Create a new <see cref="Builder"/>.</summary>
            public Builder()
            {
            }

            /// <summary>Build the session parameters.</summary>
            /// <returns>The session parameters.</returns>
            public SessionParameters Build()
            {
                Validate(m_cipherSuite >= 0, "cipherSuite");
                Validate(m_masterSecret != null, "masterSecret");
                return new SessionParameters(m_cipherSuite, m_localCertificate, m_masterSecret, m_negotiatedVersion,
                    m_peerCertificate, m_pskIdentity, m_srpIdentity, m_encodedServerExtensions, m_extendedMasterSecret);
            }

            /// <summary>Set the cipher suite.</summary>
            /// <param name="cipherSuite">The cipher suite.</param>
            /// <returns>This builder.</returns>
            public Builder SetCipherSuite(int cipherSuite)
            {
                this.m_cipherSuite = cipherSuite;
                return this;
            }

            /// <summary>Set whether the extended master secret was used.</summary>
            /// <param name="extendedMasterSecret">true if the extended master secret was used, false otherwise.</param>
            /// <returns>This builder.</returns>
            public Builder SetExtendedMasterSecret(bool extendedMasterSecret)
            {
                this.m_extendedMasterSecret = extendedMasterSecret;
                return this;
            }

            /// <summary>Set the local certificate.</summary>
            /// <param name="localCertificate">The local certificate.</param>
            /// <returns>This builder.</returns>
            public Builder SetLocalCertificate(Certificate localCertificate)
            {
                this.m_localCertificate = localCertificate;
                return this;
            }

            /// <summary>Set the master secret.</summary>
            /// <param name="masterSecret">The master secret.</param>
            /// <returns>This builder.</returns>
            public Builder SetMasterSecret(TlsSecret masterSecret)
            {
                this.m_masterSecret = masterSecret;
                return this;
            }

            /// <summary>Set the negotiated version.</summary>
            /// <param name="negotiatedVersion">The negotiated version.</param>
            /// <returns>This builder.</returns>
            public Builder SetNegotiatedVersion(ProtocolVersion negotiatedVersion)
            {
                this.m_negotiatedVersion = negotiatedVersion;
                return this;
            }

            /// <summary>Set the peer certificate.</summary>
            /// <param name="peerCertificate">The peer certificate.</param>
            /// <returns>This builder.</returns>
            public Builder SetPeerCertificate(Certificate peerCertificate)
            {
                this.m_peerCertificate = peerCertificate;
                return this;
            }

            /// <summary>Set the PSK identity.</summary>
            /// <param name="pskIdentity">The PSK identity.</param>
            /// <returns>This builder.</returns>
            public Builder SetPskIdentity(byte[] pskIdentity)
            {
                this.m_pskIdentity = pskIdentity;
                return this;
            }

            /// <summary>Set the SRP identity.</summary>
            /// <param name="srpIdentity">The SRP identity.</param>
            /// <returns>This builder.</returns>
            public Builder SetSrpIdentity(byte[] srpIdentity)
            {
                this.m_srpIdentity = srpIdentity;
                return this;
            }

            /// <exception cref="IOException"/>
            public Builder SetServerExtensions(IDictionary<int, byte[]> serverExtensions)
            {
                if (serverExtensions == null || serverExtensions.Count < 1)
                {
                    this.m_encodedServerExtensions = null;
                }
                else
                {
                    MemoryStream buf = new MemoryStream();
                    TlsProtocol.WriteExtensions(buf, serverExtensions);
                    this.m_encodedServerExtensions = buf.ToArray();
                }
                return this;
            }

            private void Validate(bool condition, string parameter)
            {
                if (!condition)
                    throw new InvalidOperationException("Required session parameter '" + parameter + "' not configured");
            }
        }

        private readonly int m_cipherSuite;
        private readonly Certificate m_localCertificate;
        private readonly TlsSecret m_masterSecret;
        private readonly ProtocolVersion m_negotiatedVersion;
        private readonly Certificate m_peerCertificate;
        private readonly byte[] m_pskIdentity;
        private readonly byte[] m_srpIdentity;
        private readonly byte[] m_encodedServerExtensions;
        private readonly bool m_extendedMasterSecret;

        private SessionParameters(int cipherSuite, Certificate localCertificate, TlsSecret masterSecret,
            ProtocolVersion negotiatedVersion, Certificate peerCertificate, byte[] pskIdentity, byte[] srpIdentity,
            byte[] encodedServerExtensions, bool extendedMasterSecret)
        {
            this.m_cipherSuite = cipherSuite;
            this.m_localCertificate = localCertificate;
            this.m_masterSecret = masterSecret;
            this.m_negotiatedVersion = negotiatedVersion;
            this.m_peerCertificate = peerCertificate;
            this.m_pskIdentity = Arrays.Clone(pskIdentity);
            this.m_srpIdentity = Arrays.Clone(srpIdentity);
            this.m_encodedServerExtensions = encodedServerExtensions;
            this.m_extendedMasterSecret = extendedMasterSecret;
        }

        /// <summary>Gets the cipher suite.</summary>
        public int CipherSuite
        {
            get { return m_cipherSuite; }
        }

        /// <summary>Clear the secret data of the session parameters.</summary>
        public void Clear()
        {
            if (m_masterSecret != null)
            {
                m_masterSecret.Destroy();
            }
        }

        /// <summary>Create a copy of the session parameters.</summary>
        /// <returns>The copy.</returns>
        public SessionParameters Copy()
        {
            return new SessionParameters(m_cipherSuite, m_localCertificate, m_masterSecret, m_negotiatedVersion,
                m_peerCertificate, m_pskIdentity, m_srpIdentity, m_encodedServerExtensions, m_extendedMasterSecret);
        }

        /// <summary>Gets a value indicating whether this is extended master secret.</summary>
        public bool IsExtendedMasterSecret
        {
            get { return m_extendedMasterSecret; }
        }

        /// <summary>Gets the local certificate.</summary>
        public Certificate LocalCertificate
        {
            get { return m_localCertificate; }
        }

        /// <summary>Gets the master secret.</summary>
        public TlsSecret MasterSecret
        {
            get { return m_masterSecret; }
        }

        /// <summary>Gets the negotiated version.</summary>
        public ProtocolVersion NegotiatedVersion
        {
            get { return m_negotiatedVersion; }
        }

        /// <summary>Gets the peer certificate.</summary>
        public Certificate PeerCertificate
        {
            get { return m_peerCertificate; }
        }

        /// <summary>Gets the psk identity.</summary>
        public byte[] PskIdentity
        {
            get { return m_pskIdentity; }
        }

        /// <exception cref="IOException"/>
        public IDictionary<int, byte[]> ReadServerExtensions()
        {
            if (m_encodedServerExtensions == null)
                return null;

            return TlsProtocol.ReadExtensions(new MemoryStream(m_encodedServerExtensions, false));
        }

        /// <summary>Gets the srp identity.</summary>
        public byte[] SrpIdentity
        {
            get { return m_srpIdentity; }
        }
    }
}
