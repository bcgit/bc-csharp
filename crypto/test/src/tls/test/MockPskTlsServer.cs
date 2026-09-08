using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>The test PSK server, for the pre-1.3 PSK cipher suites; see <see cref="MockPskDtlsServer"/> for its
    /// DTLS configuration.</summary>
    internal class MockPskTlsServer
        : PskTlsServer
    {
        protected string m_peerName = "TLS-PSK server";

        internal MockPskTlsServer(bool badKey = false)
            : base(new BcTlsCrypto(), new MyIdentityManager(badKey))
        {
        }

        /*
         * Knobs.
         */

        internal int HandshakeTimeoutMillis { get; set; } = 0;

        internal int HandshakeResendTimeMillis { get; set; } = 1000;

        internal ProtocolVersion[] SupportedVersions { get; set; } = ProtocolVersion.TLSv12.Only();

        public override int GetHandshakeTimeoutMillis() => HandshakeTimeoutMillis;

        public override int GetHandshakeResendTimeMillis() => HandshakeResendTimeMillis;

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

        protected override ProtocolVersion[] GetSupportedVersions() => SupportedVersions;

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TlsTestUtilities.LogAlert(m_peerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(m_peerName, false, alertLevel, alertDescription, null, null);

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            TlsTestUtilities.Log(m_peerName + " negotiated version " + serverVersion);

            return serverVersion;
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsTestUtilities.LogHandshakeComplete(m_peerName, m_context);

            byte[] pskIdentity = m_context.SecurityParameters.PskIdentity;
            if (pskIdentity != null)
            {
                TlsTestUtilities.Log(m_peerName + " completed handshake for PSK identity: "
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

        /// <summary>Knows the one test client identity.</summary>
        internal class MyIdentityManager
            : TlsPskIdentityManager
        {
            private readonly bool m_badKey;

            internal MyIdentityManager(bool badKey)
            {
                m_badKey = badKey;
            }

            public byte[] GetHint() => Strings.ToUtf8ByteArray("hint");

            public byte[] GetPsk(byte[] identity)
            {
                if (identity != null)
                {
                    string name = Strings.FromUtf8ByteArray(identity);
                    if (name.Equals("client"))
                        return TlsTestUtilities.GetPskPasswordUtf8(m_badKey);
                }
                return null;
            }
        }
    }
}
