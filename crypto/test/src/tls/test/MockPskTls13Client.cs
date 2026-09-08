using System;
using System.Collections.Generic;

using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    internal class MockPskTls13Client
        : AbstractTlsClient
    {
        private const string PeerName = "TLS 1.3 PSK client";

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

        protected override IList<ProtocolName> GetProtocolNames() =>
            new List<ProtocolName>{ ProtocolName.Http_1_1, ProtocolName.Http_2_Tls };

        protected override int[] GetSupportedCipherSuites() =>
            TlsUtilities.GetSupportedCipherSuites(Crypto, new int[]{ CipherSuite.TLS_AES_128_GCM_SHA256 });

        protected override ProtocolVersion[] GetSupportedVersions() => ProtocolVersion.TLSv13.Only();

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
            TlsTestUtilities.LogAlert(PeerName, true, alertLevel, alertDescription, message, cause);
        }

        public override void NotifyAlertReceived(short alertLevel, short alertDescription) =>
            TlsTestUtilities.LogAlert(PeerName, false, alertLevel, alertDescription, null, null);

        public override void NotifySelectedPsk(TlsPsk selectedPsk)
        {
            if (null == selectedPsk)
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }

        public override void NotifyServerVersion(ProtocolVersion serverVersion)
        {
            base.NotifyServerVersion(serverVersion);

            TlsTestUtilities.Log(PeerName + " negotiated version " + serverVersion);
        }

        public override TlsAuthentication GetAuthentication() =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            TlsTestUtilities.LogHandshakeComplete(PeerName, m_context);
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            TlsTestUtilities.CheckClientRandom(m_context);

            return base.GetClientExtensions();
        }

        public override void ProcessServerExtensions(IDictionary<int, byte[]> serverExtensions)
        {
            TlsTestUtilities.CheckServerRandom(m_context);

            base.ProcessServerExtensions(serverExtensions);
        }
    }
}
