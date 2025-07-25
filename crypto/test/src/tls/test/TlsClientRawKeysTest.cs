using System;
using System.IO;
using System.Net.Sockets;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS server.</summary>
    /// <remarks>
    /// <code>
    /// openssl genpkey -out ed25519.priv -algorithm ed25519
    /// openssl pkey -in ed25519.priv -pubout -out ed25519.pub
    /// 
    /// gnutls-serv --http --debug 10 --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub
    /// </code>
    /// </remarks>
    [TestFixture]
    public class TlsClientRawKeysTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            string host = "localhost";
            int port = 5556;

            RunTest(host, port, ProtocolVersion.TLSv12);
            RunTest(host, port, ProtocolVersion.TLSv13);
        }

        private static void RunTest(string host, int port, ProtocolVersion tlsVersion)
        {
            MockRawKeysTlsClient client = new MockRawKeysTlsClient(CertificateType.RawPublicKey,
                CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey },
                new short[]{ CertificateType.RawPublicKey }, new Ed25519PrivateKeyParameters(new SecureRandom()),
                tlsVersion);
            TlsClientProtocol protocol = OpenTlsClientConnection(host, port, client);

            using (var s = protocol.Stream)
            {
                Http11Get(host, port, s);
            }
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

                string upperLine = line.ToUpperInvariant();

                // TEST CODE ONLY. This is not a robust way of parsing the result!
                foreach (string end in ends)
                {
                    if (upperLine.IndexOf(end) >= 0)
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
