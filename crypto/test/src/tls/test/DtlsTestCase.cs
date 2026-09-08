using System;

using NUnit.Framework;

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

            TlsTestClientImpl clientImpl = new TlsTestClientImpl(config);
            TlsTestServerImpl serverImpl = new TlsTestServerImpl(config);

            LoopbackResult result = DtlsLoopback.Run(clientImpl, serverImpl, null,
                () => new DtlsTestClientProtocol(config));

            if (config.expectFatalAlertConnectionEnd == -1)
            {
                result.ThrowIfFailed();
            }

            Assert.AreEqual(config.expectFatalAlertConnectionEnd, clientImpl.FirstFatalAlertConnectionEnd,
                "Client fatal alert connection end");
            Assert.AreEqual(config.expectFatalAlertConnectionEnd, serverImpl.FirstFatalAlertConnectionEnd,
                "Server fatal alert connection end");

            Assert.AreEqual(config.expectFatalAlertDescription, clientImpl.FirstFatalAlertDescription,
                "Client fatal alert description");
            Assert.AreEqual(config.expectFatalAlertDescription, serverImpl.FirstFatalAlertDescription,
                "Server fatal alert description");
        }
    }
}
