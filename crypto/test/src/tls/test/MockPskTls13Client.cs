using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTls13Client
        : AbstractTlsClient
    {
        private readonly bool m_badKey;

        internal MockPskTls13Client(bool badKey = false)
            : base(new BcTlsCrypto())
        {
            m_badKey = badKey;
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

        protected override IList<ProtocolName> GetProtocolNames()
        {
            var protocolNames = new List<ProtocolName>();
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

        public override IList<TlsPskExternal> GetExternalPsks()
        {
            byte[] identity = Strings.ToUtf8ByteArray("client");
            TlsSecret key = Crypto.CreateSecret(TlsTestUtilities.GetPskPasswordUtf8(m_badKey));
            int prfAlgorithm = PrfAlgorithm.tls13_hkdf_sha256;

            return TlsUtilities.VectorOfOne<TlsPskExternal>(new BasicTlsPskExternal(identity, key, prfAlgorithm));
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

            Console.WriteLine("TLS 1.3 PSK client negotiated version " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication()
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            var securityParameters = m_context.SecurityParameters;

            ProtocolName protocolName = securityParameters.ApplicationProtocol;
            if (protocolName != null)
            {
                Console.WriteLine("Client ALPN: " + protocolName.GetUtf8Decoding());
            }

            int negotiatedGroup = securityParameters.NegotiatedGroup;
            if (negotiatedGroup >= 0)
            {
                Console.WriteLine("Client negotiated group: " + NamedGroup.GetText(negotiatedGroup));
            }
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            if (m_context.SecurityParameters.ClientRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            return base.GetClientExtensions();
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            if (m_context.SecurityParameters.ServerRandom == null)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            base.ProcessServerExtensions(serverExtensions);
        }
    }
}
