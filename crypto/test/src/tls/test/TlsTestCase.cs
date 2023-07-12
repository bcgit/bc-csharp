using System;
using System.IO;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class TlsTestCase
    {
        private static void CheckTlsVersions(ProtocolVersion[] versions)
        {
            if (versions != null)
            {
                for (int i = 0; i < versions.Length; ++i)
                {
                    if (!versions[i].IsTls)
                        throw new InvalidOperationException("Non-TLS version");
                }
            }
        }

        [Test, TestCaseSource(typeof(TlsTestSuite), "Suite")]
        public void RunTest(TlsTestConfig config)
        {
            // Disable the test if it is not being run via TlsTestSuite
            if (config == null)
                return;

            CheckTlsVersions(config.clientSupportedVersions);
            CheckTlsVersions(config.serverSupportedVersions);

            PipedStream clientPipe = new PipedStream();
            PipedStream serverPipe = new PipedStream(clientPipe);

            NetworkStream clientNet = new NetworkStream(clientPipe);
            NetworkStream serverNet = new NetworkStream(serverPipe);

            TlsTestClientProtocol clientProtocol = new TlsTestClientProtocol(clientNet, config);
            TlsTestServerProtocol serverProtocol = new TlsTestServerProtocol(serverNet, config);

            clientProtocol.IsResumableHandshake = true;
            serverProtocol.IsResumableHandshake = true;

            TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
            TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

            ServerTask serverTask = new ServerTask(this, serverProtocol, serverImpl);
            Thread serverThread = new Thread(new ThreadStart(serverTask.Run));
            serverThread.Start();

            Exception caught = null;
            try
            {
                clientProtocol.Connect(clientImpl);

                byte[] data = new byte[1000];
                clientImpl.Crypto.SecureRandom.NextBytes(data);

                Stream stream = clientProtocol.Stream;
                stream.Write(data, 0, data.Length);

                byte[] echo = new byte[data.Length];
                int count = Streams.ReadFully(stream, echo, 0, echo.Length);

                Assert.AreEqual(count, data.Length);
                Assert.IsTrue(Arrays.AreEqual(data, echo));

                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsKeyingMaterial1, serverImpl.m_tlsKeyingMaterial1));
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsKeyingMaterial2, serverImpl.m_tlsKeyingMaterial2));
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsServerEndPoint, serverImpl.m_tlsServerEndPoint));

                if (!TlsUtilities.IsTlsV13(clientImpl.m_negotiatedVersion))
                {
                    Assert.NotNull(clientImpl.m_tlsUnique);
                    Assert.NotNull(serverImpl.m_tlsUnique);
                }
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsUnique, serverImpl.m_tlsUnique));

                stream.Close();
            }
            catch (Exception e)
            {
                caught = e;
                LogException(caught);
            }

            serverTask.AllowExit();
            serverThread.Join();

            Assert.IsTrue(clientNet.IsClosed, "Client Stream not closed");
            Assert.IsTrue(serverNet.IsClosed, "Server Stream not closed");

            Assert.AreEqual(config.expectFatalAlertConnectionEnd, clientImpl.FirstFatalAlertConnectionEnd,
                "Client fatal alert connection end");
            Assert.AreEqual(config.expectFatalAlertConnectionEnd, serverImpl.FirstFatalAlertConnectionEnd,
                "Server fatal alert connection end");

            Assert.AreEqual(config.expectFatalAlertDescription, clientImpl.FirstFatalAlertDescription,
                "Client fatal alert description");
            Assert.AreEqual(config.expectFatalAlertDescription, serverImpl.FirstFatalAlertDescription,
                "Server fatal alert description");

            if (config.expectFatalAlertConnectionEnd == -1)
            {
                Assert.IsNull(caught, "Unexpected client exception");
                Assert.IsNull(serverTask.m_caught, "Unexpected server exception");
            }
        }

        protected virtual void LogException(Exception e)
        {
            if (TlsTestConfig.Debug)
            {
                Console.Error.WriteLine(e);
                Console.Error.Flush();
            }
        }

        internal class ServerTask
        {
            protected readonly TlsTestCase m_outer;
            protected readonly TlsServerProtocol m_serverProtocol;
            protected readonly TlsServer m_server;

            internal bool m_canExit = false;
            internal Exception m_caught = null;

            internal ServerTask(TlsTestCase outer, TlsTestServerProtocol serverProtocol, TlsServer server)
            {
                this.m_outer = outer;
                this.m_serverProtocol = serverProtocol;
                this.m_server = server;
            }

            internal void AllowExit()
            {
                lock (this)
                {
                    m_canExit = true;
                    Monitor.PulseAll(this);
                }
            }

            public void Run()
            {
                try
                {
                    m_serverProtocol.Accept(m_server);
                    Streams.PipeAll(m_serverProtocol.Stream, m_serverProtocol.Stream);
                    m_serverProtocol.Close();
                }
                catch (Exception e)
                {
                    m_caught = e;
                    m_outer.LogException(m_caught);
                }

                WaitExit();
            }

            protected void WaitExit()
            {
                lock (this)
                {
                    while (!m_canExit)
                    {
                        try
                        {
                            Monitor.Wait(this);
                        }
                        catch (ThreadInterruptedException)
                        {
                        }
                    }
                }
            }
        }
    }
}
