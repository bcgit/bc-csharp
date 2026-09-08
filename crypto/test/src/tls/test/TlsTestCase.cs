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

            TlsTestSuite.AssertExpectedOutcome(config, clientImpl, serverImpl, result);

            Assert.IsTrue(result.ClientStreamClosed, "Client Stream not closed");
            Assert.IsTrue(result.ServerStreamClosed, "Server Stream not closed");

            if (config.expectFatalAlertConnectionEnd == -1)
            {
                Assert.IsTrue(Arrays.AreEqual(clientImpl.TlsKeyingMaterial1, serverImpl.TlsKeyingMaterial1));
                Assert.IsTrue(Arrays.AreEqual(clientImpl.TlsKeyingMaterial2, serverImpl.TlsKeyingMaterial2));
                Assert.IsTrue(Arrays.AreEqual(clientImpl.TlsServerEndPoint, serverImpl.TlsServerEndPoint));

                if (!TlsUtilities.IsTlsV13(clientImpl.NegotiatedVersion))
                {
                    Assert.NotNull(clientImpl.TlsUnique);
                    Assert.NotNull(serverImpl.TlsUnique);
                }
                Assert.IsTrue(Arrays.AreEqual(clientImpl.TlsUnique, serverImpl.TlsUnique));
            }
        }
    }
}
