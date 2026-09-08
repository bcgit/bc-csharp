using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockTlsServer
        : DefaultTlsServer
    {
        private const string PeerName = "TLS server";

        internal MockTlsServer()
            : base(new BcTlsCrypto())
        {
        }

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

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
            TlsTestUtilities.LogAlert(PeerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(PeerName, false, alertLevel, alertDescription, null, null);

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            TlsTestUtilities.Log(PeerName + " negotiated version " + serverVersion);

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

            TlsTestUtilities.LogHandshakeComplete(PeerName, m_context);
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

        protected override TlsCredentialedSigner GetRsaSignerCredentials()
        {
            return TlsTestUtilities.LoadSignerCredentialsServer(m_context, m_context.SecurityParameters.ClientSigAlgs,
                SignatureAlgorithm.rsa);
        }
    }
}
