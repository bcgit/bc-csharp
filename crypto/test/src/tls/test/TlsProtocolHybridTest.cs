using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsProtocolHybridTest
    {
        // mismatched hybrid groups w/o non-hybrids
        [Test]
        public void TestMismatchedGroups()
        {
            MockTlsHybridClient client = new MockTlsHybridClient(null);
            MockTlsHybridServer server = new MockTlsHybridServer();

            client.SetNamedGroups(new int[]{ NamedGroup.SecP256r1MLKEM768 });
            server.SetNamedGroups(new int[]{ NamedGroup.X25519MLKEM768 });

            LoopbackResult result = TlsLoopback.Run(client, server);

            Assert.IsInstanceOf<TlsFatalAlert>(result.ServerException, "server should have rejected the handshake");
            Assert.NotNull(result.ClientException, "client should have failed");
        }

        [Test]
        public void TestCurveSM2MLKEM768()
        {
            ImplTestClientServer(NamedGroup.curveSM2MLKEM768);
        }

        [Test]
        public void TestSecP256r1MLKEM768()
        {
            ImplTestClientServer(NamedGroup.SecP256r1MLKEM768);
        }

        [Test]
        public void TestSecP384r1MLKEM1024()
        {
            ImplTestClientServer(NamedGroup.SecP384r1MLKEM1024);
        }

        [Test]
        public void TestX25519MLKEM768()
        {
            ImplTestClientServer(NamedGroup.X25519MLKEM768);
        }

        private void ImplTestClientServer(int hybridGroup)
        {
            MockTlsHybridClient client = new MockTlsHybridClient(null);
            MockTlsHybridServer server = new MockTlsHybridServer();

            client.SetNamedGroups(new int[]{ hybridGroup });
            server.SetNamedGroups(new int[]{ hybridGroup });

            TlsLoopback.Run(client, server).ThrowIfFailed();
        }
    }
}
