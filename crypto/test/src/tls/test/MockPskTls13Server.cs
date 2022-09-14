using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTls13Server
        : AbstractTlsServer
    {
        internal MockPskTls13Server()
            : base(new BcTlsCrypto(new SecureRandom()))
        {
        }

        public override TlsCredentials GetCredentials()
        {
            return null;
        }

        protected override IList<ProtocolName> GetProtocolNames()
        {
            var protocolNames = new List<ProtocolName>();
            protocolNames.Add(ProtocolName.Http_2_Tls);
            protocolNames.Add(ProtocolName.Http_1_1);
            return protocolNames;
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto,
                new int[] { CipherSuite.TLS_AES_128_CCM_8_SHA256, CipherSuite.TLS_AES_128_CCM_SHA256,
                    CipherSuite.TLS_AES_128_GCM_SHA256, CipherSuite.TLS_CHACHA20_POLY1305_SHA256 });
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv13.Only();
        }

        public override ProtocolVersion GetServerVersion()
        {
            ProtocolVersion serverVersion = base.GetServerVersion();

            Console.WriteLine("TLS 1.3 PSK server negotiated " + serverVersion);

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
                    TlsSecret key = Crypto.CreateSecret(Strings.ToUtf8ByteArray("TLS_TEST_PSK"));
                    int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;

                    return new BasicTlsPskExternal(identity, key, prfAlgorithm);
                }
            }
            return null;
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS 1.3 PSK server raised alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
            if (message != null)
            {
                output.WriteLine("> " + message);
            }
            if (cause != null)
            {
                output.WriteLine(cause);
            }
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS 1.3 PSK server received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Server ALPN: " + protocolName.GetUtf8Decoding());
            }
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessClientExtensions(clientExtensions);
        }

        public override IDictionary<int, byte[]> GetServerExtensions()
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetServerExtensions();
        }

        public override void GetServerExtensionsForConnection(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.GetServerExtensionsForConnection(serverExtensions);
        }
    }
}
