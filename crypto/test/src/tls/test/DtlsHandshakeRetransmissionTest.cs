using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsHandshakeRetransmissionTest
    {
        [Test]
        public void TestClientServer()
        {
            MockDtlsClient client = new MockDtlsClient(null);
            MockDtlsServer server = new MockDtlsServer();

            DtlsLoopbackOptions options = new DtlsLoopbackOptions
            {
                UseCookieExchange = true,
                ClientTransportDecorator = transport => new ServerHandshakeDropper(transport, true),
            };

            DtlsLoopback.Run(client, server, options).ThrowIfFailed();
        }
    }
}
