using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [NonParallelizable] // Minimize timeout problems
    [TestFixture]
    public class DtlsPskProtocolTest
    {
        [Parallelizable]
        [Test]
        public void BadClientKeyTimeout()
        {
            MockPskDtlsClient client = new MockPskDtlsClient(null, badKey: true);
            MockPskDtlsServer server = new MockPskDtlsServer();

            ImplTestKeyMismatch(client, server);
        }

        [Parallelizable]
        [Test]
        public void BadServerKeyTimeout()
        {
            MockPskDtlsClient client = new MockPskDtlsClient(null);
            MockPskDtlsServer server = new MockPskDtlsServer(badKey: true);

            ImplTestKeyMismatch(client, server);
        }

        [Parallelizable]
        [Test]
        public void TestClientServer()
        {
            MockPskDtlsClient client = new MockPskDtlsClient(null);
            MockPskDtlsServer server = new MockPskDtlsServer();

            DtlsLoopbackOptions options = new DtlsLoopbackOptions
            {
                HandshakePacketLossPercent = 10,
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }

        private static void ImplTestKeyMismatch(MockPskDtlsClient client, MockPskDtlsServer server)
        {
            // The client must be the end that times out: a server timeout would reach the client as an alert first
            server.HandshakeTimeoutMillis = 2 * client.HandshakeTimeoutMillis;

            // No unreliable transport here: the focus is the timeout caused by the bad PSK
            LoopbackResult result = DtlsLoopback.Run(client, server);

            Assert.IsInstanceOf<TlsTimeoutException>(result.ClientException, "client should have timed out");
        }
    }
}
