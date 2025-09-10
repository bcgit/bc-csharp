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
        // mismatched ML-KEM groups w/o classical crypto
        [Test]
        public void TestMismatchedGroups()
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            MockTlsKemClient client = new MockTlsKemClient(null);
            MockTlsKemServer server = new MockTlsKemServer();

            client.SetNamedGroups(new int[]{ NamedGroup.MLKEM512 });
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
        public void TestMLKEM512()
        {
            ImplTestClientServer(NamedGroup.MLKEM512);
        }

        [Test]
        public void TestMLKEM768()
        {
            ImplTestClientServer(NamedGroup.MLKEM768);
        }

        [Test]
        public void TestMLKEM1024()
        {
            ImplTestClientServer(NamedGroup.MLKEM1024);
        }

        private void ImplTestClientServer(int kemGroup)
        {
            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            TlsClientProtocol clientProtocol = new TlsClientProtocol(clientPipe);
            TlsServerProtocol serverProtocol = new TlsServerProtocol(serverPipe);

            MockTlsKemClient client = new MockTlsKemClient(null);
            MockTlsKemServer server = new MockTlsKemServer();

            client.SetNamedGroups(new int[]{ kemGroup });
            server.SetNamedGroups(new int[]{ kemGroup });

            ServerTask serverTask = new ServerTask(serverProtocol, server, shouldFail: false);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            clientProtocol.Connect(client);

            byte[] data = new byte[1000];
            client.Crypto.SecureRandom.NextBytes(data);

            using (var stream = clientProtocol.Stream)
            {
                stream.Write(data, 0, data.Length);

                byte[] echo = new byte[data.Length];
                int count = Streams.ReadFully(stream, echo);

                Assert.AreEqual(count, data.Length);
                Assert.IsTrue(Arrays.AreEqual(data, echo));
            }

            serverThread.Join();
        }

        internal class ServerTask
        {
            private readonly TlsServerProtocol m_serverProtocol;
            private readonly TlsServer m_server;
            private readonly bool m_shouldFail;

            internal ServerTask(TlsServerProtocol serverProtocol, TlsServer server, bool shouldFail)
            {
                m_serverProtocol = serverProtocol;
                m_server = server;
                m_shouldFail = shouldFail;
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

                        using (var stream = m_serverProtocol.Stream)
                        {
                            Streams.PipeAll(stream, stream);
                        }
                    }
                    catch (IOException)
                    {
                        if (!m_shouldFail)
                        {
                            Assert.Fail();
                        }
                    }
                }
                catch (Exception)
                {
                }
            }
        }
    }
}
