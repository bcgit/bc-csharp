using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>
    /// Support for the [Explicit] tests that talk to an external TLS peer over TCP, e.g. an OpenSSL or GnuTLS
    /// command-line client or server. See GnuTLSSetup.html and OpenSSLSetup.html (under 'docs') and the x509-*.pem
    /// files under tls/credentials in bc-test-data for configuring such a peer.
    /// </summary>
    internal static class ExternalPeerUtilities
    {
        internal const string DefaultHost = "localhost";
        internal const int DefaultPort = 5556;

        /// <summary>Connect to an external server and complete the handshake.</summary>
        internal static TlsClientProtocol Connect(string hostname, int port, TlsClient client)
        {
            TcpClient tcp = new TcpClient(hostname, port);

            TlsClientProtocol protocol = new TlsClientProtocol(tcp.GetStream());
            protocol.Connect(client);
            return protocol;
        }

        /// <summary>Make a minimal HTTP/1.1 GET request over an established connection and print the response.
        /// </summary>
        internal static void Http11Get(Stream s)
        {
            WriteUtf8Line(s, "GET / HTTP/1.1");
            WriteUtf8Line(s, "");
            s.Flush();

            Console.WriteLine("---");

            string[] ends = new string[]{ "</HTML>", "HTTP/1.1 3", "HTTP/1.1 4" };

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

        /// <summary>
        /// Accept connections from external clients, serving each on its own thread with a server from the factory
        /// (which is given the connection's index) and echoing what the client sends while copying it to stdout.
        /// </summary>
        /// <param name="connectionLimit">How many connections to accept, or a negative value to accept forever.
        /// </param>
        internal static void Serve(int port, Func<int, TlsServer> serverFactory, int connectionLimit)
        {
            TcpListener ss = new TcpListener(IPAddress.Any, port);
            ss.Start();
            Stream stdout = Console.OpenStandardOutput();
            try
            {
                for (int index = 0; connectionLimit < 0 || index < connectionLimit; ++index)
                {
                    TcpClient s = ss.AcceptTcpClient();
                    Console.WriteLine("----------------------------------------------------------------------------");
                    Console.WriteLine("Accepted " + s);
                    ServerTask serverTask = new ServerTask(s, stdout, serverFactory(index));
                    Thread t = new Thread(serverTask.Run);
                    t.Start();
                }
            }
            finally
            {
                ss.Stop();
            }
        }

        private static void WriteUtf8Line(Stream output, string line)
        {
            byte[] buf = Strings.ToUtf8ByteArray(line + "\r\n");
            output.Write(buf, 0, buf.Length);
            Console.WriteLine(">>> " + line);
        }

        private sealed class ServerTask
        {
            private readonly TcpClient m_tcp;
            private readonly Stream m_stdout;
            private readonly TlsServer m_server;

            internal ServerTask(TcpClient tcp, Stream stdout, TlsServer server)
            {
                m_tcp = tcp;
                m_stdout = stdout;
                m_server = server;
            }

            internal void Run()
            {
                try
                {
                    TlsServerProtocol serverProtocol = new TlsServerProtocol(m_tcp.GetStream());
                    serverProtocol.Accept(m_server);

                    using (var stream = serverProtocol.Stream)
                    {
                        // NB: We don't dispose this directly to avoid disposing stdout
                        Stream log = new TeeOutputStream(stream, m_stdout);

                        Streams.PipeAll(stream, log);
                    }
                }
                finally
                {
                    try
                    {
                        m_tcp.Close();
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }
    }
}
