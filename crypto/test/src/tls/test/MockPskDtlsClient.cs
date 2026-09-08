namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A <see cref="MockPskTlsClient"/> configured for DTLS 1.2, with a short handshake timeout so that a
    /// PSK mismatch (which in DTLS shows as retransmission until timeout) fails quickly.</summary>
    internal class MockPskDtlsClient
        : MockPskTlsClient
    {
        internal MockPskDtlsClient(TlsSession session, bool badKey = false)
            : this(session, TlsTestUtilities.CreateDefaultPskIdentity(badKey))
        {
        }

        internal MockPskDtlsClient(TlsSession session, TlsPskIdentity pskIdentity)
            : base(session, pskIdentity)
        {
            m_peerName = "DTLS-PSK client";

            AddTestExtensions = false;
            HandshakeTimeoutMillis = 1000;
            HandshakeResendTimeMillis = 100; // Fast resend only for tests!
            SupportedVersions = ProtocolVersion.DTLSv12.Only();
        }
    }
}
