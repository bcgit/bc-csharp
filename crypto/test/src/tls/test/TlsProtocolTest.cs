using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            MockTlsClient client = new MockTlsClient(null);
            MockTlsServer server = new MockTlsServer();

            TlsLoopback.Run(client, server).ThrowIfFailed();
        }
    }
}
