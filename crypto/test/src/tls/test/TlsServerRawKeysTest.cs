using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    /// <summary>A simple test designed to conduct a TLS handshake with an external TLS client.</summary>
    /// <remarks>
    /// <code>
    /// gnutls-cli --rawpkkeyfile ed25519.priv --rawpkfile ed25519.pub --priority NORMAL:+CTYPE-CLI-RAWPK:+CTYPE-SRV-RAWPK --insecure --debug 10 --port 5556 localhost
    /// </code>
    /// </remarks>
    [TestFixture]
    public class TlsServerRawKeysTest
    {
        [Test, Explicit]
        public void TestConnection()
        {
            int port = 5556;
            ProtocolVersion[] tlsVersions = ProtocolVersion.TLSv13.DownTo(ProtocolVersion.TLSv12);

            TcpListener ss = new TcpListener(IPAddress.Any, port);
            ss.Start();
            Stream stdout = Console.OpenStandardOutput();
            try
            {
                foreach (var tlsVersion in tlsVersions)
                {
                    TcpClient s = ss.AcceptTcpClient();
                    Console.WriteLine("--------------------------------------------------------------------------------");
                    Console.WriteLine("Accepted " + s);
                    ServerTask serverTask = new ServerTask(s, stdout, tlsVersion);
                    Thread t = new Thread(new ThreadStart(serverTask.Run));
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
            private readonly ProtocolVersion tlsVersion;

            internal ServerTask(TcpClient s, Stream stdout, ProtocolVersion tlsVersion)
            {
                this.s = s;
                this.stdout = stdout;
                this.tlsVersion = tlsVersion;
            }

            public void Run()
            {
                try
                {
                    MockRawKeysTlsServer server = new MockRawKeysTlsServer(CertificateType.RawPublicKey,
                        CertificateType.RawPublicKey, new short[]{ CertificateType.RawPublicKey },
                        new Ed25519PrivateKeyParameters(new SecureRandom()), tlsVersion);
                    TlsServerProtocol serverProtocol = new TlsServerProtocol(s.GetStream());
                    serverProtocol.Accept(server);
                    Stream log = new TeeOutputStream(serverProtocol.Stream, stdout);
                    Streams.PipeAll(serverProtocol.Stream, log);
                    serverProtocol.Close();
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
