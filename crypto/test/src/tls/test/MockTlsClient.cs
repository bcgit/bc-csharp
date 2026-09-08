using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// The configurable test client: trusts the test server certificates, authenticates with the RSA test client
    /// certificate when asked, records what the handshake produced, and can be steered by a few knobs (set before the
    /// handshake) so that a scenario need not subclass it. Scenarios that do subclass it have two seams,
    /// <see cref="VerifyServerCertificate"/> and <see cref="SelectClientCredentials"/>.
    /// </summary>
    internal class MockTlsClient
        : DefaultTlsClient
    {
        protected string m_peerName = "TLS client";

        internal TlsSession m_session;

        internal MockTlsClient(TlsSession session)
            : this(new BcTlsCrypto(), session)
        {
        }

        internal MockTlsClient(TlsCrypto crypto, TlsSession session)
            : base(crypto)
        {
            this.m_session = session;
        }

        /*
         * Knobs. Null means the library default.
         */

        /// <summary>Whether to add the extensions of <see cref="TlsTestUtilities.AddTestClientExtensions"/>.
        /// </summary>
        internal bool AddTestExtensions { get; set; } = true;

        internal int HandshakeTimeoutMillis { get; set; } = 0;

        internal int HandshakeResendTimeMillis { get; set; } = 1000;

        /// <summary>The named groups to offer, whatever their roles.</summary>
        internal int[] NamedGroups { get; set; } = null;

        internal IList<ProtocolName> ProtocolNames { get; set; } =
            new List<ProtocolName>{ ProtocolName.Http_1_1, ProtocolName.Http_2_Tls };

        internal ProtocolVersion[] SupportedVersions { get; set; } = null;

        /*
         * What the handshake produced.
         */

        /// <summary>The <see cref="ConnectionEnd"/> that raised the first fatal alert, or -1 if there was none.
        /// </summary>
        internal int FirstFatalAlertConnectionEnd { get; private set; } = -1;

        /// <summary>The <see cref="AlertDescription"/> of the first fatal alert, or -1 if there was none.</summary>
        internal short FirstFatalAlertDescription { get; private set; } = -1;

        internal ProtocolVersion NegotiatedVersion { get; private set; } = null;

        /// <summary>Exported keying material, where extended_master_secret allows it.</summary>
        internal byte[] TlsKeyingMaterial1 { get; private set; } = null;
        internal byte[] TlsKeyingMaterial2 { get; private set; } = null;

        internal byte[] TlsServerEndPoint { get; private set; } = null;
        internal byte[] TlsUnique { get; private set; } = null;

        public override int GetHandshakeTimeoutMillis() => HandshakeTimeoutMillis;

        public override int GetHandshakeResendTimeMillis() => HandshakeResendTimeMillis;

        protected override IList<ProtocolName> GetProtocolNames() => ProtocolNames;

        public override TlsSession GetSessionToResume() => m_session;

        protected override IList<int> GetSupportedGroups(IList<int> namedGroupRoles)
        {
            if (NamedGroups == null)
                return base.GetSupportedGroups(namedGroupRoles);

            var supportedGroups = new List<int>();
            TlsUtilities.AddIfSupported(supportedGroups, Crypto, NamedGroups);
            return supportedGroups;
        }

        protected override ProtocolVersion[] GetSupportedVersions() =>
            SupportedVersions ?? base.GetSupportedVersions();

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            NoteFatalAlert(ConnectionEnd.client, alertLevel, alertDescription);

            TlsTestUtilities.LogAlert(m_peerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            NoteFatalAlert(ConnectionEnd.server, alertLevel, alertDescription);

            TlsTestUtilities.LogAlert(m_peerName, false, alertLevel, alertDescription, null, null);
        }

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

            NegotiatedVersion = serverVersion;

            TlsTestUtilities.Log(m_peerName + " negotiated version " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication() => new MyTlsAuthentication(this);

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            SecurityParameters securityParameters = m_context.SecurityParameters;
            if (securityParameters.IsExtendedMasterSecret)
            {
                TlsKeyingMaterial1 = m_context.ExportKeyingMaterial("BC_TLS_TESTS_1", null, 16);
                TlsKeyingMaterial2 = m_context.ExportKeyingMaterial("BC_TLS_TESTS_2", new byte[8], 16);
            }

            TlsServerEndPoint = m_context.ExportChannelBinding(ChannelBinding.tls_server_end_point);
            TlsUnique = m_context.ExportChannelBinding(ChannelBinding.tls_unique);

            TlsTestUtilities.LogHandshakeComplete(m_peerName, m_context);

            m_session = TlsTestUtilities.NoteSession(m_peerName, m_session, m_context);
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            base.ProcessServerExtensions(serverExtensions);
        }

        /// <summary>Check the server's certificate; by default, that it is one of the test server certificates.
        /// </summary>
        protected virtual void VerifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            TlsTestUtilities.VerifyServerCertificate(m_context, serverCertificate,
                TlsTestUtilities.TrustedServerCertResources, checkSigAlgs: true);
        }

        /// <summary>Choose the client credentials; by default, the RSA test client certificate.</summary>
        protected virtual TlsCredentials SelectClientCredentials(CertificateRequest certificateRequest) =>
            TlsTestUtilities.SelectRsaClientCredentials(m_context, certificateRequest);

        private void NoteFatalAlert(int connectionEnd, short alertLevel, short alertDescription)
        {
            if (alertLevel == AlertLevel.fatal && FirstFatalAlertConnectionEnd == -1)
            {
                FirstFatalAlertConnectionEnd = connectionEnd;
                FirstFatalAlertDescription = alertDescription;
            }
        }

        private sealed class MyTlsAuthentication
            : TlsAuthentication
        {
            private readonly MockTlsClient m_outer;

            internal MyTlsAuthentication(MockTlsClient outer)
            {
                m_outer = outer;
            }

            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) =>
                m_outer.VerifyServerCertificate(serverCertificate);

            public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest) =>
                m_outer.SelectClientCredentials(certificateRequest);
        }
    }
}
