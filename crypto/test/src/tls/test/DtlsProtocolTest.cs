using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            MockDtlsClient client = new MockDtlsClient(null);
            MockDtlsServer server = new MockDtlsServer();

            DtlsLoopbackOptions options = new DtlsLoopbackOptions
            {
                UseCookieExchange = true,
                HandshakePacketLossPercent = 10,
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }

        /// <summary>A full handshake, with client authentication, under heavy loss: most flights need several
        /// attempts.</summary>
        [Test]
        public void TestClientServerHighLoss()
        {
            MockDtlsClient client = new MockDtlsClient(null);
            MockDtlsServer server = new MockDtlsServer();

            DtlsLoopbackOptions options = new DtlsLoopbackOptions
            {
                UseCookieExchange = true,
                HandshakePacketLossPercent = 25,
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }
    }
}
