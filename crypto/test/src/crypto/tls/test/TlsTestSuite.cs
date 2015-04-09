using System;
using System.Collections;

using NUnit.Framework;

namespace Org.BouncyCastle.Crypto.Tls.Tests
{
    public class TlsTestSuite
    {
        // Make the access to constants less verbose 
        internal class C : TlsTestConfig {}

        public TlsTestSuite()
        {
        }

        public static IEnumerable Suite()
        {
            IList testSuite = new ArrayList();

            AddFallbackTests(testSuite);
            AddVersionTests(testSuite, ProtocolVersion.TLSv10);
            AddVersionTests(testSuite, ProtocolVersion.TLSv11);
            AddVersionTests(testSuite, ProtocolVersion.TLSv12);

            return testSuite;
        }

        private static void AddFallbackTests(IList testSuite)
        {
            {
                TlsTestConfig c = CreateTlsTestConfig(ProtocolVersion.TLSv12);
                c.clientFallback = true;

                testSuite.Add(new TestCaseData(c).SetName("FallbackGood"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(ProtocolVersion.TLSv12);
                c.clientOfferVersion = ProtocolVersion.TLSv11;
                c.clientFallback = true;
                c.ExpectServerFatalAlert(AlertDescription.inappropriate_fallback);

                testSuite.Add(new TestCaseData(c).SetName("FallbackBad"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(ProtocolVersion.TLSv12);
                c.clientOfferVersion = ProtocolVersion.TLSv11;

                testSuite.Add(new TestCaseData(c).SetName("FallbackNone"));
            }
        }

        private static void AddVersionTests(IList testSuite, ProtocolVersion version)
        {
            string prefix = version.ToString()
                .Replace(" ", "")
                .Replace("\\", "")
                .Replace(".", "")
                + "_";

            {
                TlsTestConfig c = CreateTlsTestConfig(version);

                testSuite.Add(new TestCaseData(c).SetName(prefix + "GoodDefault"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
                c.ExpectServerFatalAlert(AlertDescription.decrypt_error);

                testSuite.Add(new TestCaseData(c).SetName(prefix + "BadCertificateVerify"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
                c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

                testSuite.Add(new TestCaseData(c).SetName(prefix + "BadClientCertificate"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_NONE;
                c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
                c.ExpectServerFatalAlert(AlertDescription.handshake_failure);

                testSuite.Add(new TestCaseData(c).SetName(prefix + "BadMandatoryCertReqDeclined"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version);
                c.serverCertReq = C.SERVER_CERT_REQ_NONE;

                testSuite.Add(new TestCaseData(c).SetName(prefix + "GoodNoCertReq"));
            }

            {
                TlsTestConfig c = CreateTlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_NONE;

                testSuite.Add(new TestCaseData(c).SetName(prefix + "GoodOptionalCertReqDeclined"));
            }
        }

        private static TlsTestConfig CreateTlsTestConfig(ProtocolVersion version)
        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientMinimumVersion = ProtocolVersion.TLSv10;
            c.clientOfferVersion = ProtocolVersion.TLSv12;
            c.serverMaximumVersion = version;
            c.serverMinimumVersion = ProtocolVersion.TLSv10;
            return c;
        }
    }
}
