namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A <see cref="MockTlsServer"/> configured for DTLS 1.2.</summary>
    internal class MockDtlsServer
        : MockTlsServer
    {
        internal MockDtlsServer()
        {
            m_peerName = "DTLS server";

            HandshakeResendTimeMillis = 100;
            ProtocolNames = null;
            SupportedVersions = ProtocolVersion.DTLSv12.Only();
        }
    }
}
