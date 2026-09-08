using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTlsClient
        : PskTlsClient
    {
        private const string PeerName = "TLS-PSK client";

        private static readonly string[] TrustedServerCertResources = new string[]{ "x509-server-rsa-enc.pem" };

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

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_1_1, ProtocolName.Http_2_Tls };

        public override TlsSession GetSessionToResume() => m_session;

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TlsTestUtilities.LogAlert(PeerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(PeerName, false, alertLevel, alertDescription, null, null);

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            TlsTestUtilities.CheckClientRandom(m_context);

            var clientExtensions = TlsExtensionsUtilities.EnsureExtensionsInitialised(base.GetClientExtensions());
            TlsTestUtilities.AddTestClientExtensions(clientExtensions, m_context);
            return clientExtensions;
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            TlsTestUtilities.Log(PeerName + " negotiated version " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication() => new MyTlsAuthentication(m_context);

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsTestUtilities.LogHandshakeComplete(PeerName, m_context);

            m_session = TlsTestUtilities.NoteSession(PeerName, m_session, m_context);
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            base.ProcessServerExtensions(serverExtensions);
        }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

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
