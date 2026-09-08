using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTls13Server
        : AbstractTlsServer
    {
        private const string PeerName = "TLS 1.3 PSK server";

        private readonly bool m_badKey;

        internal MockPskTls13Server(bool badKey = false)
            : base(new BcTlsCrypto())
        {
            m_badKey = badKey;
        }

        public override TlsCredentials GetCredentials() => null;

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto,
                new int[]{ CipherSuite.TLS_AES_128_CCM_8_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256,
                    CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256 });
        }

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            TlsTestUtilities.Log(PeerName + " negotiated version " + serverVersion);

            return serverVersion;
        }

        public override TlsPskExternal GetExternalPsk(IList<PskIdentity> identities)
        {
            byte[] identity = Strings.ToUtf8ByteArray("client");
            long obfuscatedTicketAge = 0L;

            PskIdentity matchIdentity = new PskIdentity(identity, obfuscatedTicketAge);

            for (int i = 0, count = identities.Count; i < count; ++i)
            {
                if (matchIdentity.Equals(identities[i]))
                {
                    TlsSecret key = Crypto.CreateSecret(TlsTestUtilities.GetPskPasswordUtf8(m_badKey));
                    int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;

                    return new BasicTlsPskExternal(identity, key, prfAlgorithm);
                }
            }
            return null;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TlsTestUtilities.LogAlert(PeerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(PeerName, false, alertLevel, alertDescription, null, null);

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
    }
}
