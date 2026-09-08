using NUnit.Framework;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS server.</summary>
    /// <remarks>
    /// <code>
    /// openssl genpkey -out ed25519.priv -algorithm ed25519
    /// openssl pkey -in ed25519.priv -pubout -out ed25519.pub
    ///
    /// gnutls-serv --http --debug 10 --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub
    /// </code>
    /// </remarks>
    [TestFixture]
    public class TlsClientRawKeysTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            string host = ExternalPeerUtilities.DefaultHost;
            int port = ExternalPeerUtilities.DefaultPort;

            RunTest(host, port, ProtocolVersion.TLSv12);
            RunTest(host, port, ProtocolVersion.TLSv13);
        }

        private static void RunTest(string host, int port, ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(new BcTlsCrypto(), CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey },
                new short[]{ CertificateType.RawPublicKey }, tlsVersion);
            TlsClientProtocol protocol = ExternalPeerUtilities.Connect(host, port, client);

            using (var s = protocol.Stream)
            {
                ExternalPeerUtilities.Http11Get(s);
            }
        }
    }
}
