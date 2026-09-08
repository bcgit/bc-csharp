using NUnit.Framework;

using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS client.</summary>
    /// <remarks>
    /// <code>
    /// gnutls-cli --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --insecure --debug 10 --port 5556 localhost
    /// </code>
    /// </remarks>
    [TestFixture]
    public class TlsServerRawKeysTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            // One connection per version, TLS 1.3 first
            ProtocolVersion[] tlsVersions = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);

            ExternalPeerUtilities.Serve(ExternalPeerUtilities.DefaultPort,
                index => new MockRawKeysTlsServer(new BcTlsCrypto(), CertificateType.RawPublicKey,
                    CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey }, tlsVersions[index]),
                tlsVersions.Length);
        }
    }
}
