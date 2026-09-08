using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;

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

            TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
            TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

            LoopbackResult result = TlsLoopback.Run(clientImpl, serverImpl,
                stream => new TlsTestClientProtocol(stream, config));

            if (config.expectFatalAlertConnectionEnd == -1)
            {
                result.ThrowIfFailed();
            }

            Assert.IsTrue(result.ClientStreamClosed, "Client Stream not closed");
            Assert.IsTrue(result.ServerStreamClosed, "Server Stream not closed");

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
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsKeyingMaterial1, serverImpl.m_tlsKeyingMaterial1));
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsKeyingMaterial2, serverImpl.m_tlsKeyingMaterial2));
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsServerEndPoint, serverImpl.m_tlsServerEndPoint));

                if (!TlsUtilities.IsTlsV13(clientImpl.m_negotiatedVersion))
                {
                    Assert.NotNull(clientImpl.m_tlsUnique);
                    Assert.NotNull(serverImpl.m_tlsUnique);
                }
                Assert.IsTrue(Arrays.AreEqual(clientImpl.m_tlsUnique, serverImpl.m_tlsUnique));
            }
        }
    }
}
