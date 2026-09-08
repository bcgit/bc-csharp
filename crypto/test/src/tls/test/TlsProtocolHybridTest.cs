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
            MockTlsClient client = CreateClient(NamedGroup.SecP256r1MLKEM768);
            MockTlsServer server = CreateServer(NamedGroup.X25519MLKEM768);

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

        private static void ImplTestClientServer(int hybridGroup)
        {
            TlsLoopback.Run(CreateClient(hybridGroup), CreateServer(hybridGroup)).ThrowIfFailed();
        }

        private static MockTlsClient CreateClient(int namedGroup)
        {
            return new MockTlsClient(null)
            {
                NamedGroups = new int[]{ namedGroup },
                SupportedVersions = ProtocolVersion.TLSv13.Only(),
            };
        }

        private static MockTlsServer CreateServer(int namedGroup)
        {
            return new MockTlsServer
            {
                NamedGroups = new int[]{ namedGroup },
                SupportedVersions = ProtocolVersion.TLSv13.Only(),
            };
        }
    }
}
