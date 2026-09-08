using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS server.</summary>
    /// <remarks>
    /// See <see cref="ExternalPeerUtilities"/> for help configuring an external TLS server. Extra options are
    /// required to enable PSK ciphersuites and configure identities/keys.
    /// </remarks>
    [TestFixture]
    public class PskTlsClientTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            string host = ExternalPeerUtilities.DefaultHost;
            int port = ExternalPeerUtilities.DefaultPort;

            long time1 = DateTimeUtilities.CurrentUnixMs();

            /*
             * Note: This is the default PSK identity for 'openssl s_server' testing, the server must be
             * started with "-psk 6161616161" to make the keys match, and possibly the "-psk_hint"
             * option should be present.
             */
            //string psk_identity = "Client_identity";
            //byte[] psk = new byte[] { 0x61, 0x61, 0x61, 0x61, 0x61 };
            //TlsPskIdentity pskIdentity = new BasicTlsPskIdentity(psk_identity, psk);

            // This corresponds to the configuration of MockPskTlsServer
            TlsPskIdentity pskIdentity = TlsTestUtilities.CreateDefaultPskIdentity(false);

            MockPskTlsClient client = new MockPskTlsClient(null, pskIdentity);
            TlsClientProtocol protocol = ExternalPeerUtilities.Connect(host, port, client);
            protocol.Close();

            long time2 = DateTimeUtilities.CurrentUnixMs();
            Console.WriteLine("Elapsed 1: " + (time2 - time1) + "ms");

            client = new MockPskTlsClient(client.GetSessionToResume(), pskIdentity);
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
