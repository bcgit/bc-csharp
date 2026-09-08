using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsProtocolKemTest
    {
        // mismatched ML-KEM groups w/o classical crypto
        [Test]
        public void TestMismatchedGroups()
        {
            MockTlsKemClient client = new MockTlsKemClient(null);
            MockTlsKemServer server = new MockTlsKemServer();

            client.SetNamedGroups(new int[]{ NamedGroup.MLKEM512 });
            server.SetNamedGroups(new int[]{ NamedGroup.MLKEM768 });

            LoopbackResult result = TlsLoopback.Run(client, server);

            Assert.IsInstanceOf<TlsFatalAlert>(result.ServerException, "server should have rejected the handshake");
            Assert.NotNull(result.ClientException, "client should have failed");
        }

        [Test]
        public void TestMLKEM512()
        {
            ImplTestClientServer(NamedGroup.MLKEM512);
        }

        [Test]
        public void TestMLKEM768()
        {
            ImplTestClientServer(NamedGroup.MLKEM768);
        }

        [Test]
        public void TestMLKEM1024()
        {
            ImplTestClientServer(NamedGroup.MLKEM1024);
        }

        private void ImplTestClientServer(int kemGroup)
        {
            MockTlsKemClient client = new MockTlsKemClient(null);
            MockTlsKemServer server = new MockTlsKemServer();

            client.SetNamedGroups(new int[]{ kemGroup });
            server.SetNamedGroups(new int[]{ kemGroup });

            TlsLoopback.Run(client, server).ThrowIfFailed();
        }
    }
}
