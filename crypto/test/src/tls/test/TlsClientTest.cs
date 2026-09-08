using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS server.</summary>
    /// <remarks>See <see cref="ExternalPeerUtilities"/> for help configuring an external TLS server.</remarks>
    [TestFixture]
    public class TlsClientTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            string host = ExternalPeerUtilities.DefaultHost;
            int port = ExternalPeerUtilities.DefaultPort;

            long time1 = DateTimeUtilities.CurrentUnixMs();

            MockTlsClient client = new MockTlsClient(null);
            TlsClientProtocol protocol = ExternalPeerUtilities.Connect(host, port, client);
            protocol.Close();

            long time2 = DateTimeUtilities.CurrentUnixMs();
            Console.WriteLine("Elapsed 1: " + (time2 - time1) + "ms");

            client = new MockTlsClient(client.GetSessionToResume());
            protocol = ExternalPeerUtilities.Connect(host, port, client);

            long time3 = DateTimeUtilities.CurrentUnixMs();
            Console.WriteLine("Elapsed 2: " + (time3 - time2) + "ms");

            using (var s = protocol.Stream)
            {
                ExternalPeerUtilities.Http11Get(s);
            }
        }
    }
}
