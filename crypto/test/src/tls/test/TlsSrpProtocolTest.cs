using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsSrpProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            MockSrpTlsClient client = new MockSrpTlsClient(null, MockSrpTlsServer.TEST_SRP_IDENTITY);
            MockSrpTlsServer server = new MockSrpTlsServer();

            TlsLoopback.Run(client, server).ThrowIfFailed();
        }
    }
}
