using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS client.</summary>
    /// <remarks>
    /// Please refer to GnuTLSSetup.html or OpenSSLSetup.html (under 'docs'), and x509-*.pem files in this package
    /// (under 'src/test/resources') for help configuring an external TLS client.
    /// </remarks>
    [TestFixture]
    public class PskTlsServerTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            int port = 5556;

            TcpListener ss = new TcpListener(IPAddress.Any, port);
            ss.Start();
            Stream stdout = Console.OpenStandardOutput();
            try
            {
                while (true)
                {
                    TcpClient s = ss.AcceptTcpClient();
                    Console.WriteLine("--------------------------------------------------------------------------------");
                    Console.WriteLine("Accepted " + s);
                    ServerTask serverTask = new ServerTask(s, stdout);
                    Thread t = new Thread(serverTask.Run);
                    t.Start();
                }
            }
            finally
            {
                ss.Stop();
            }
        }

        internal class ServerTask
        {
            private readonly TcpClient s;
            private readonly Stream stdout;

            internal ServerTask(TcpClient s, Stream stdout)
            {
                this.s = s;
                this.stdout = stdout;
            }

            public void Run()
            {
                try
                {
                    MockPskTlsServer server = new MockPskTlsServer();
                    TlsServerProtocol serverProtocol = new TlsServerProtocol(s.GetStream());
                    serverProtocol.Accept(server);

                    using (var stream = serverProtocol.Stream)
                    {
                        // NB: We don't dispose this directly to avoid disposing stdout
                        Stream log = new TeeOutputStream(stream, stdout);

                        Streams.PipeAll(stream, log);
                    }
                }
                finally
                {
                    try
                    {
                        s.Close();
                    }
                    catch (IOException)
                    {
                    }
                }
            }
        }
    }
}
