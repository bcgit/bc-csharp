using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS server.</summary>
    /// <remarks>
    /// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in this package
    /// (under 'src/test/resources') for help configuring an external TLS server.
    /// </remarks>
    [TestFixture]
    public class TlsClientTest
    {
        [Test, Ignore]
        public void TestConnection()
        {
            string host = "localhost";
            int port = 5556;

            long time1 = DateTimeUtilities.CurrentUnixMs();

            MockTlsClient client = new MockTlsClient(null);
            TlsClientProtocol protocol = OpenTlsClientConnection(host, port, client);
            protocol.Close();

            long time2 = DateTimeUtilities.CurrentUnixMs();
            Console.WriteLine("Elapsed 1: " + (time2 - time1) + "ms");

            client = new MockTlsClient(client.GetSessionToResume());
            protocol = OpenTlsClientConnection(host, port, client);

            long time3 = DateTimeUtilities.CurrentUnixMs();
            Console.WriteLine("Elapsed 2: " + (time3 - time2) + "ms");

            Http11Get(host, port, protocol.Stream);

            protocol.Close();
        }

        private static void Http11Get(string host, int port, Stream s)
        {
            WriteUtf8Line(s, "GET / HTTP/1.1");
            //WriteUtf8Line(s, "Host: " + host + ":" + port);
            WriteUtf8Line(s, "");
            s.Flush();

            Console.WriteLine("---");

            string[] ends = new string[] { "</HTML>", "HTTP/1.1 3", "HTTP/1.1 4" };

            StreamReader reader = new StreamReader(s);

            bool finished = false;
            string line;
            while (!finished && (line = reader.ReadLine()) != null)
            {
                Console.WriteLine("<<< " + line);

                string upperLine = TlsTestUtilities.ToUpperInvariant(line);

                // TEST CODE ONLY. This is not a robust way of parsing the result!
                foreach (string end in ends)
                {
                    if (upperLine.Contains(end))
                    {
                        finished = true;
                        break;
                    }
                }
            }

            Console.Out.Flush();
        }

        private static TlsClientProtocol OpenTlsClientConnection(string hostname, int port, TlsClient client)
        {
            TcpClient tcp = new TcpClient(hostname, port);

            TlsClientProtocol protocol = new TlsClientProtocol(tcp.GetStream());
            protocol.Connect(client);
            return protocol;
        }

        private static void WriteUtf8Line(Stream output, string line)
        {
            byte[] buf = Encoding.UTF8.GetBytes(line + "\r\n");
            output.Write(buf, 0, buf.Length);
            Console.WriteLine(">>> " + line);
        }
    }
}
