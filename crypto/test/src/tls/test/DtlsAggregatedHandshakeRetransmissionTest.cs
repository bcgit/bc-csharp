using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsAggregatedHandshakeRetransmissionTest
    {
        [Test]
        public void TestClientServer()
        {
            MockDtlsClient client = new MockDtlsClient(null);
            MockDtlsServer server = new MockDtlsServer();

            client.HandshakeTimeoutMillis = 30000;    // Test gets stuck, so we need it to time out.

            DtlsLoopbackOptions options = new DtlsLoopbackOptions
            {
                UseCookieExchange = true,
                ClientTransportDecorator = transport =>
                    new MinimalHandshakeAggregator(new ServerHandshakeDropper(transport, true), false, true),
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }
    }
}
