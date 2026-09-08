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
            MockTlsClient client = CreateClient(NamedGroup.MLKEM512);
            MockTlsServer server = CreateServer(NamedGroup.MLKEM768);

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

        private static void ImplTestClientServer(int kemGroup)
        {
            TlsLoopback.Run(CreateClient(kemGroup), CreateServer(kemGroup)).ThrowIfFailed();
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
