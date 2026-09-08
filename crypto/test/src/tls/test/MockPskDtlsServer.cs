namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A <see cref="MockPskTlsServer"/> configured for DTLS 1.2, with a short handshake timeout so that a
    /// PSK mismatch (which in DTLS shows as retransmission until timeout) fails quickly.</summary>
    internal class MockPskDtlsServer
        : MockPskTlsServer
    {
        internal MockPskDtlsServer(bool badKey = false)
            : base(badKey)
        {
            m_peerName = "DTLS-PSK server";

            HandshakeTimeoutMillis = 1000;
            HandshakeResendTimeMillis = 100; // Fast resend only for tests!
            SupportedVersions = ProtocolVersion.DTLSv12.Only();
        }
    }
}
