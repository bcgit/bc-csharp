using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// The configurable test server: authenticates with the test server certificates, requests and checks a client
    /// certificate against the test client certificates, records what the handshake produced, and can be steered by
    /// a few knobs (set before the handshake) so that a scenario need not subclass it.
    /// </summary>
    internal class MockTlsServer
        : DefaultTlsServer
    {
        protected string m_peerName = "TLS server";

        internal MockTlsServer()
            : this(new BcTlsCrypto())
        {
        }

        internal MockTlsServer(TlsCrypto crypto)
            : base(crypto)
        {
        }

        /*
         * Knobs. Null means the library default.
         */

        internal int HandshakeResendTimeMillis { get; set; } = 1000;

        internal int[] NamedGroups { get; set; } = null;

        internal IList<ProtocolName> ProtocolNames { get; set; } =
            new List<ProtocolName>{ ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

        internal ProtocolVersion[] SupportedVersions { get; set; } = null;

        /*
         * What the handshake produced.
         */

        /// <summary>The <see cref="ConnectionEnd"/> that raised the first fatal alert, or -1 if there was none.
        /// </summary>
        internal int FirstFatalAlertConnectionEnd { get; private set; } = -1;

        /// <summary>The <see cref="AlertDescription"/> of the first fatal alert, or -1 if there was none.</summary>
        internal short FirstFatalAlertDescription { get; private set; } = -1;

        /// <summary>Exported keying material, where extended_master_secret allows it.</summary>
        internal byte[] TlsKeyingMaterial1 { get; private set; } = null;
        internal byte[] TlsKeyingMaterial2 { get; private set; } = null;

        internal byte[] TlsServerEndPoint { get; private set; } = null;
        internal byte[] TlsUnique { get; private set; } = null;

        public override int GetHandshakeResendTimeMillis() => HandshakeResendTimeMillis;

        protected override IList<ProtocolName> GetProtocolNames() => ProtocolNames;

        public override int[] GetSupportedGroups() => NamedGroups ?? base.GetSupportedGroups();

        protected override ProtocolVersion[] GetSupportedVersions() =>
            SupportedVersions ?? base.GetSupportedVersions();

        public override TlsCredentials GetCredentials()
        {
            /*
             * TODO[tls13] Should really be finding the first client-supported signature scheme that the
             * server also supports and has credentials for.
             */
            if (TlsUtilities.IsTlsV13(m_context))
                return GetRsaSignerCredentials();

            return base.GetCredentials();
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            NoteFatalAlert(ConnectionEnd.server, alertLevel, alertDescription);

            TlsTestUtilities.LogAlert(m_peerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            NoteFatalAlert(ConnectionEnd.client, alertLevel, alertDescription);

            TlsTestUtilities.LogAlert(m_peerName, false, alertLevel, alertDescription, null, null);
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            TlsTestUtilities.Log(m_peerName + " negotiated version " + serverVersion);

            return serverVersion;
        }

        public override CertificateRequest GetCertificateRequest() =>
            TlsTestUtilities.CreateCertificateRequest(m_context, null);

        public override void NotifyClientCertificate(Certificate clientCertificate)
        {
            TlsTestUtilities.VerifyClientCertificate(m_context, clientCertificate,
                TlsTestUtilities.TrustedClientCertResources, checkSigAlgs: true);
        }

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
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            TlsTestUtilities.CheckClientRandom(m_context);

            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            base.GetServerExtensionsForConnection(serverExtensions);
        }

        protected override TlsCredentialedDecryptor GetRsaEncryptionCredentials() =>
            TlsTestUtilities.LoadServerEncryptionCredentials(m_context);

        protected override TlsCredentialedSigner GetRsaSignerCredentials() =>
            TlsTestUtilities.LoadSignerCredentialsServer(m_context, GetServerSigAlgs(), SignatureAlgorithm.rsa);

        /// <summary>The signature algorithms to choose the server's signing credentials from; by default, whatever
        /// the client declared.</summary>
        protected virtual IList<SignatureAndHashAlgorithm> GetServerSigAlgs() =>
            m_context.SecurityParameters.ClientSigAlgs;

        private void NoteFatalAlert(int connectionEnd, short alertLevel, short alertDescription)
        {
            if (alertLevel == AlertLevel.fatal && FirstFatalAlertConnectionEnd == -1)
            {
                FirstFatalAlertConnectionEnd = connectionEnd;
                FirstFatalAlertDescription = alertDescription;
            }
        }
    }
}
