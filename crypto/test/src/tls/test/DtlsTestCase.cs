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

            TlsTestSuite.AssertExpectedOutcome(config, clientImpl, serverImpl, result);
        }
    }
}
