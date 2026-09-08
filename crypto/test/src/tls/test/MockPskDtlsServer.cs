using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskDtlsServer
        : PskTlsServer
    {
        private const string PeerName = "DTLS-PSK server";

        internal MockPskDtlsServer(bool badKey = false)
            : base(new BcTlsCrypto(), new MockPskTlsServer.MyIdentityManager(badKey))
        {
        }

        public override int GetHandshakeTimeoutMillis() => 1000;

        public override int GetHandshakeResendTimeMillis() => 100; // Fast resend only for tests!

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

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsTestUtilities.LogHandshakeComplete(PeerName, m_context);

            byte[] pskIdentity = m_context.SecurityParameters.PskIdentity;
            if (pskIdentity != null)
            {
                TlsTestUtilities.Log(PeerName + " completed handshake for PSK identity: "
                    + Strings.FromUtf8ByteArray(pskIdentity));
            }
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

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.DTLSv12.Only();
    }
}
