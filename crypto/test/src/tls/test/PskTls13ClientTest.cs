using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS 1.3 PSK handshake with an external TLS server.</summary>
    /// <remarks>See <see cref="ExternalPeerUtilities"/> for help configuring an external TLS server.</remarks>
    [TestFixture]
    public class PskTls13ClientTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            string host = ExternalPeerUtilities.DefaultHost;
            int port = ExternalPeerUtilities.DefaultPort;

            long time0 = DateTimeUtilities.CurrentUnixMs();

            MockPskTls13Client client = new MockPskTls13Client();
            TlsClientProtocol protocol = ExternalPeerUtilities.Connect(host, port, client);

            long time1 = DateTimeUtilities.CurrentUnixMs();
            Console.WriteLine("Elapsed: " + (time1 - time0) + "ms");

            using (var s = protocol.Stream)
            {
                ExternalPeerUtilities.Http11Get(s);
            }
        }
    }
}
