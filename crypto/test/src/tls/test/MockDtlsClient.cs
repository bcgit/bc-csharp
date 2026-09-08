namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A <see cref="MockTlsClient"/> configured for DTLS 1.2.</summary>
    internal class MockDtlsClient
        : MockTlsClient
    {
        internal MockDtlsClient(TlsSession session)
            : base(session)
        {
            m_peerName = "DTLS client";

            AddTestExtensions = false;
            ProtocolNames = null;
            SupportedVersions = ProtocolVersion.DTLSv12.Only();
        }
    }
}
