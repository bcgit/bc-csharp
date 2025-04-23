using System;
using System.Text;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsProtocolTest
    {
        [Test]
        public void TestClientServer()
        {
            SecureRandom secureRandom = new SecureRandom();

            DtlsClientProtocol clientProtocol = new DtlsClientProtocol();
            DtlsServerProtocol serverProtocol = new DtlsServerProtocol();

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            ServerTask serverTask = new ServerTask(serverProtocol, network.Server);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            DatagramTransport clientTransport = network.Client;

            clientTransport = new UnreliableDatagramTransport(clientTransport, secureRandom, 0, 0);

            clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);

            MockDtlsClient client = new MockDtlsClient(null);

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

            serverTask.Shutdown(serverThread);
        }

        internal class ServerTask
        {
            private readonly DtlsServerProtocol m_serverProtocol;
            private readonly DatagramTransport m_serverTransport;
            private volatile bool m_isShutdown = false;

            internal ServerTask(DtlsServerProtocol serverProtocol, DatagramTransport serverTransport)
            {
                this.m_serverProtocol = serverProtocol;
                this.m_serverTransport = serverTransport;
            }

            public void Run()
            {
                try
                {
                    TlsCrypto serverCrypto = new BcTlsCrypto();

                    DtlsRequest request = null;

                    // Use DtlsVerifier to require a HelloVerifyRequest cookie exchange before accepting
                    {
                        DtlsVerifier verifier = new DtlsVerifier(serverCrypto);

                        // NOTE: Test value only - would typically be the client IP address
                        byte[] clientID = Encoding.UTF8.GetBytes("MockDtlsClient");

                        int receiveLimit = m_serverTransport.GetReceiveLimit();
                        int dummyOffset = serverCrypto.SecureRandom.Next(16) + 1;
                        byte[] buf = new byte[dummyOffset + m_serverTransport.GetReceiveLimit()];

                        do
                        {
                            if (m_isShutdown)
                                return;

                            int length = m_serverTransport.Receive(buf, dummyOffset, receiveLimit, 100);
                            if (length > 0)
                            {
                                request = verifier.VerifyRequest(clientID, buf, dummyOffset, length, m_serverTransport);
                            }
                        }
                        while (request == null);
                    }

                    // NOTE: A real server would handle each DtlsRequest in a new task/thread and continue accepting
                    {
                        MockDtlsServer server = new MockDtlsServer(serverCrypto);
                        DtlsTransport dtlsTransport = m_serverProtocol.Accept(server, m_serverTransport, request);
                        byte[] buf = new byte[dtlsTransport.GetReceiveLimit()];
                        while (!m_isShutdown)
                        {
                            int length = dtlsTransport.Receive(buf, 0, buf.Length, 100);
                            if (length >= 0)
                            {
                                dtlsTransport.Send(buf, 0, length);
                            }
                        }
                        dtlsTransport.Close();
                    }
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
