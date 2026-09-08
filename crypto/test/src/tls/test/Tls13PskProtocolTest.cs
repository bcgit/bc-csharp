using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class Tls13PskProtocolTest
    {
        [Test]
        public void BadClientKey()
        {
            MockPskTls13Client client = new MockPskTls13Client(badKey: true);
            MockPskTls13Server server = new MockPskTls13Server();

            TlsLoopback.Run(client, server).AssertClientReceivedFatalAlert(AlertDescription.decrypt_error);
        }

        [Test]
        public void BadServerKey()
        {
            MockPskTls13Client client = new MockPskTls13Client();
            MockPskTls13Server server = new MockPskTls13Server(badKey: true);

            TlsLoopback.Run(client, server).AssertClientReceivedFatalAlert(AlertDescription.decrypt_error);
        }

        [Test]
        public void TestClientServer()
        {
            MockPskTls13Client client = new MockPskTls13Client();
            MockPskTls13Server server = new MockPskTls13Server();

            TlsLoopback.Run(client, server).ThrowIfFailed();
        }
    }
}
