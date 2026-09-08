using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTlsServer
        : PskTlsServer
    {
        private const string PeerName = "TLS-PSK server";

        internal MockPskTlsServer(bool badKey = false)
            : base(new BcTlsCrypto(), new MyIdentityManager(badKey))
        {
        }

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

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

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv12.Only();

        /// <summary>Knows the one test client identity; shared with <see cref="MockPskDtlsServer"/>.</summary>
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
