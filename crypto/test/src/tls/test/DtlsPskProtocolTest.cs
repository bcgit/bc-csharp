using System;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DlsPskProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            SecureRandom secureRandom = new SecureRandom();

            DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            Server server = new Server(serverProtocol, network.Server);

            Thread serverThread = new Thread(new ThreadStart(server.Run));
            serverThread.Start();

            DatagramTransport clientTransport = network.Client;

            clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

            clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

            MockPskDtlsClient client = new MockPskDtlsClient(null);

            DtlsTransport dtlsClient = clientProtocol.Connect(client, clientTransport);

            for (int i = 1; i <= 10; ++i)
            {
                byte[] data = new byte[i];
                Arrays.Fill(data, (byte)i);
                dtlsClient.Send(data, 0, data.Length);
            }

            byte[] buf = new byte[dtlsClient.GetReceiveLimit()];
            while (dtlsClient.Receive(buf, 0, buf.Length, 100) >= 0)
            {
            }

            dtlsClient.Close();

            server.Shutdown(serverThread);
        }

        internal class Server
        {
            private readonly DtlsServerProtocol m_serverProtocol;
            private readonly DatagramTransport m_serverTransport;
            private volatile bool m_isShutdown = false;

            internal Server(DtlsServerProtocol serverProtocol, DatagramTransport serverTransport)
            {
                this.m_serverProtocol = serverProtocol;
                this.m_serverTransport = serverTransport;
            }

            public void Run()
            {
                try
                {
                    MockPskDtlsServer server = new MockPskDtlsServer();
                    DtlsTransport dtlsServer = m_serverProtocol.Accept(server, m_serverTransport);
                    byte[] buf = new byte[dtlsServer.GetReceiveLimit()];
                    while (!m_isShutdown)
                    {
                        int length = dtlsServer.Receive(buf, 0, buf.Length, 1000);
                        if (length >= 0)
                        {
                            dtlsServer.Send(buf, 0, length);
                        }
                    }
                    dtlsServer.Close();
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                    Console.Error.Flush();
                }
            }

            internal void Shutdown(Thread serverThread)
            {
                if (!m_isShutdown)
                {
                    this.m_isShutdown = true;
                    serverThread.Join();
                }
            }
        }
    }
}
