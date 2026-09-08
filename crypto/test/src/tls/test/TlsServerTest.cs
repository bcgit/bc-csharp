using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS client.</summary>
    /// <remarks>See <see cref="ExternalPeerUtilities"/> for help configuring an external TLS client.</remarks>
    [TestFixture]
    public class TlsServerTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            ExternalPeerUtilities.Serve(ExternalPeerUtilities.DefaultPort, index => new MockTlsServer(), -1);
        }
    }
}
