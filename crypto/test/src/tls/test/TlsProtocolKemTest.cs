using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsProtocolKemTest
    {
        // mismatched ML-KEM strengths w/o classical crypto
        [Test]
        public void TestMismatchStrength()
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            MockTlsKemClient client = new MockTlsKemClient(null);
            client.SetNamedGroups(new int[]{ NamedGroup.MLKEM512 });

            MockTlsKemServer server = new MockTlsKemServer();
            server.SetNamedGroups(new int[]{ NamedGroup.MLKEM768 });

            ServerTask serverTask = new ServerTask(serverProtocol, server, shouldFail: true);
            Thread serverThread = new Thread(serverTask.Run);
            try
            {
                serverThread.Start();
            }
            catch (Exception)
            {
            }

            try
            {
                clientProtocol.Connect(client);
                Assert.Fail();
            }
            catch (Exception)
            {
            }

            serverThread.Join();
        }

        [Test]
        public void TestClientServer()
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            MockTlsKemClient client = new MockTlsKemClient(null);
            MockTlsKemServer server = new MockTlsKemServer();

            ServerTask serverTask = new ServerTask(serverProtocol, server, shouldFail: false);
            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            clientProtocol.Connect(client);

            byte[] data = new byte[1000];
            client.Crypto.SecureRandom.NextBytes(data);

            Stream output = clientProtocol.Stream;
            output.Write(data, 0, data.Length);

            byte[] echo = new byte[data.Length];
            int count = Streams.ReadFully(clientProtocol.Stream, echo);

            Assert.AreEqual(count, data.Length);
            Assert.IsTrue(Arrays.AreEqual(data, echo));

            output.Close();

            serverThread.Join();
        }

        internal class ServerTask
        {
            private readonly TlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;
            private readonly bool m_shouldFail;

            internal ServerTask(TlsServerProtocol serverProtocol, TlsServer server, bool shouldFail)
            {
                this.m_serverProtocol = serverProtocol;
                this.m_server = server;
                this.m_shouldFail = shouldFail;
            }

            public void Run()
            {
                try
                {
                    try
                    {
                        m_serverProtocol.Accept(m_server);
                        if (m_shouldFail)
                        {
                            Assert.Fail();
                        }
                    }
                    catch (IOException)
                    {
                        if (!m_shouldFail)
                        {
                            Assert.Fail();
                        }
                    }

                    Streams.PipeAll(m_serverProtocol.Stream, m_serverProtocol.Stream);
                    m_serverProtocol.Close();
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
