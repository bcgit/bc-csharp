using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsPskProtocolTest
    {
        [Test]
        public void BadClientKey()
        {
            MockPskTlsClient client = new MockPskTlsClient(null, badKey: true);
            MockPskTlsServer server = new MockPskTlsServer();

            TlsLoopback.Run(client, server).AssertClientReceivedFatalAlert(AlertDescription.bad_record_mac);
        }

        [Test]
        public void BadServerKey()
        {
            MockPskTlsClient client = new MockPskTlsClient(null);
            MockPskTlsServer server = new MockPskTlsServer(badKey: true);

            TlsLoopback.Run(client, server).AssertClientReceivedFatalAlert(AlertDescription.bad_record_mac);
        }

        [Test]
        public void TestClientServer()
        {
            MockPskTlsClient client = new MockPskTlsClient(null);
            MockPskTlsServer server = new MockPskTlsServer();

            TlsLoopback.Run(client, server).ThrowIfFailed();
        }
    }
}
