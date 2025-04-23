using System;
using System.Threading;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class DtlsTestCase
    {
        private static void CheckDtlsVersions(ProtocolVersion[] versions)
        {
            if (versions != null)
            {
                for (int i = 0; i < versions.Length; ++i)
                {
                    if (!versions[i].IsDtls)
                        throw new InvalidOperationException("Non-DTLS version");
                }
            }
        }

        [Test, TestCaseSource(typeof(DtlsTestSuite), "Suite")]
        public void RunTest(TlsTestConfig config)
        {
            CheckDtlsVersions(config.clientSupportedVersions);
            CheckDtlsVersions(config.serverSupportedVersions);

            DtlsTestClientProtocol clientProtocol = new DtlsTestClientProtocol(config);
            DtlsTestServerProtocol serverProtocol = new DtlsTestServerProtocol(config);

            MockDatagramAssociation network = new MockDatagramAssociation(1500);

            TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
            TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

            ServerTask serverTask = new ServerTask(this, serverProtocol, network.Server, serverImpl);

            Thread serverThread = new Thread(serverTask.Run);
            serverThread.Start();

            Exception caught = null;
            try
            {
                DatagramTransport clientTransport = network.Client;

                if (TlsTestConfig.Debug)
                {
                    clientTransport = new LoggingDatagramTransport(clientTransport, Console.Out);
                }

                DtlsTransport dtlsClient = clientProtocol.Connect(clientImpl, clientTransport);

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
            }
            catch (Exception e)
            {
                caught = e;
                LogException(caught);
            }

            serverTask.Shutdown(serverThread);

            // TODO Add checks that the various streams were closed

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
                Assert.IsNull(serverTask.Caught, "Unexpected server exception");
            }
        }

        protected void LogException(Exception e)
        {
            if (TlsTestConfig.Debug)
            {
                Console.Error.WriteLine(e);
                Console.Error.Flush();
            }
        }

        internal class ServerTask
        {
            private readonly DtlsTestCase m_outer;
            private readonly DtlsTestServerProtocol m_serverProtocol;
            private readonly DatagramTransport m_serverTransport;
            private readonly TlsTestServerImpl m_serverImpl;

            private volatile bool m_isShutdown = false;
            private Exception m_caught = null;

            internal ServerTask(DtlsTestCase outer, DtlsTestServerProtocol serverProtocol,
                DatagramTransport serverTransport, TlsTestServerImpl serverImpl)
            {
                this.m_outer = outer;
                this.m_serverProtocol = serverProtocol;
                this.m_serverTransport = serverTransport;
                this.m_serverImpl = serverImpl;
            }

            public void Run()
            {
                try
                {
                    DtlsTransport dtlsServer = m_serverProtocol.Accept(m_serverImpl, m_serverTransport);
                    byte[] buf = new byte[dtlsServer.GetReceiveLimit()];
                    while (!m_isShutdown)
                    {
                        int length = dtlsServer.Receive(buf, 0, buf.Length, 100);
                        if (length >= 0)
                        {
                            dtlsServer.Send(buf, 0, length);
                        }
                    }
                    dtlsServer.Close();
                }
                catch (Exception e)
                {
                    this.m_caught = e;
                    m_outer.LogException(m_caught);
                }
            }

            internal void Shutdown(Thread serverThread)
            {
                if (!m_isShutdown)
                {
                    this.m_isShutdown = true;
                    //serverThread.Interrupt();
                    serverThread.Join();
                }
            }

            internal Exception Caught
            {
                get { return m_caught; }
            }
        }
    }
}
