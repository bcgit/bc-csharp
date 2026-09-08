using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>The test PSK client, for the pre-1.3 PSK cipher suites; see <see cref="MockPskDtlsClient"/> for its
    /// DTLS configuration.</summary>
    internal class MockPskTlsClient
        : PskTlsClient
    {
        private static readonly string[] TrustedServerCertResources = new string[]{ "x509-server-rsa-enc.pem" };

        protected string m_peerName = "TLS-PSK client";

        internal TlsSession m_session;

        internal MockPskTlsClient(TlsSession session, bool badKey = false)
            : this(session, TlsTestUtilities.CreateDefaultPskIdentity(badKey))
        {
        }

        internal MockPskTlsClient(TlsSession session, TlsPskIdentity pskIdentity)
            : base(new BcTlsCrypto(), pskIdentity)
        {
            this.m_session = session;
        }

        /*
         * Knobs.
         */

        /// <summary>Whether to add the extensions of <see cref="TlsTestUtilities.AddTestClientExtensions"/>.
        /// </summary>
        internal bool AddTestExtensions { get; set; } = true;

        internal int HandshakeTimeoutMillis { get; set; } = 0;

        internal int HandshakeResendTimeMillis { get; set; } = 1000;

        internal ProtocolVersion[] SupportedVersions { get; set; } = ProtocolVersion.TLSv12.Only();

        public override int GetHandshakeTimeoutMillis() => HandshakeTimeoutMillis;

        public override int GetHandshakeResendTimeMillis() => HandshakeResendTimeMillis;

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_1_1, ProtocolName.Http_2_Tls };

        public override TlsSession GetSessionToResume() => m_session;

        protected override ProtocolVersion[] GetSupportedVersions() => SupportedVersions;

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TlsTestUtilities.LogAlert(m_peerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(m_peerName, false, alertLevel, alertDescription, null, null);

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            TlsTestUtilities.CheckClientRandom(m_context);

            var clientExtensions = base.GetClientExtensions();
            if (AddTestExtensions)
            {
                clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(clientExtensions);
                TlsTestUtilities.AddTestClientExtensions(clientExtensions, m_context);
            }
            return clientExtensions;
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            TlsTestUtilities.Log(m_peerName + " negotiated version " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication() => new MyTlsAuthentication(m_context);

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsTestUtilities.LogHandshakeComplete(m_peerName, m_context);

            m_session = TlsTestUtilities.NoteSession(m_peerName, m_session, m_context);
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            base.ProcessServerExtensions(serverExtensions);
        }

        internal class MyTlsAuthentication
            : ServerOnlyTlsAuthentication
        {
            private readonly TlsContext m_context;

            internal MyTlsAuthentication(TlsContext context)
            {
                this.m_context = context;
            }

            public override void NotifyServerCertificate(TlsServerCertificate serverCertificate)
            {
                TlsTestUtilities.VerifyServerCertificate(m_context, serverCertificate, TrustedServerCertResources,
                    checkSigAlgs: true);
            }
        }
    }
}
