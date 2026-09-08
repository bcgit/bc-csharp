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
                ClientTransportDecorator = transport =>
                    new UnreliableDatagramTransport(transport, client.Crypto.SecureRandom, 0, 0),
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }
    }
}
