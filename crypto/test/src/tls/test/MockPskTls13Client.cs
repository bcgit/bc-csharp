using System;
using System.Collections;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTls13Client
        : AbstractTlsClient
    {
        internal MockPskTls13Client()
            : base(new BcTlsCrypto(new SecureRandom()))
        {
        }

        //public override IList GetEarlyKeyShareGroups()
        //{
        //    return TlsUtilities.VectorOfOne(NamedGroup.secp256r1);
        //    //return null;
        //}

        //public override short[] GetPskKeyExchangeModes()
        //{
        //    return new short[] { PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke };
        //}

        protected override IList GetProtocolNames()
        {
            IList protocolNames = new ArrayList();
            protocolNames.Add(ProtocolName.Http_1_1);
            protocolNames.Add(ProtocolName.Http_2_Tls);
            return protocolNames;
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return TlsUtilities.GetSupportedCipherSuites(Crypto, new int[] { CipherSuite.TLS_AES_128_GCM_SHA256 });
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return ProtocolVersion.TLSv13.Only();
        }

        public override IList GetExternalPsks()
        {
            byte[] identity = Strings.ToUtf8ByteArray("client");
            TlsSecret key = Crypto.CreateSecret(Strings.ToUtf8ByteArray("TLS_TEST_PSK"));
            int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;

            return TlsUtilities.VectorOfOne(new BasicTlsPskExternal(identity, key, prfAlgorithm));
        }

        public override void NotifyAlertRaised(short alertLevel, short alertDescription, string message,
            Exception cause)
        {
            TextWriter output = (alertLevel == AlertLevel.fatal) ? Console.Error : Console.Out;
            output.WriteLine("TLS 1.3 PSK client raised alert: " + AlertLevel.GetText(alertLevel)
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
            output.WriteLine("TLS 1.3 PSK client received alert: " + AlertLevel.GetText(alertLevel)
                + ", " + AlertDescription.GetText(alertDescription));
        }

        public override void NotifySelectedPsk(TlsPsk selectedPsk)
        {
            if (null == selectedPsk)
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            Console.WriteLine("TLS 1.3 PSK client negotiated " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            ProtocolName protocolName = m_context.SecurityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Client ALPN: " + protocolName.GetUtf8Decoding());
            }
        }

        public override IDictionary GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetClientExtensions();
        }

        public override void ProcessServerExtensions(IDictionary serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);
        }
    }
}
