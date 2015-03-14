using System;
using System.Collections;

using NUnit.Framework;

namespace Org.BouncyCastle.Crypto.Tls.Tests
{
    public class DtlsTestSuite
    {
        // Make the access to constants less verbose 
        internal class C : TlsTestConfig {}

        public DtlsTestSuite()
        {
        }

        public static IEnumerable Suite()
        {
            IList testSuite = new ArrayList();

            AddFallbackTests(testSuite);
            AddVersionTests(testSuite, ProtocolVersion.DTLSv10);
            AddVersionTests(testSuite, ProtocolVersion.DTLSv12);

            return testSuite;
        }

        private static void AddFallbackTests(IList testSuite)
        {
            {
                TlsTestConfig c = CreateDtlsTestConfig(ProtocolVersion.DTLSv12);
                c.clientFallback = true;

                testSuite.Add(new TestCaseData(c).SetName("FallbackGood"));
            }

            /*
             * NOTE: Temporarily disabled automatic test runs because of problems getting a clean exit
             * of the DTLS server after a fatal alert. As of writing, manual runs show the correct
             * alerts being raised
             */

            //{
            //    TlsTestConfig c = CreateDtlsTestConfig(ProtocolVersion.DTLSv12);
            //    c.clientOfferVersion = ProtocolVersion.DTLSv10;
            //    c.clientFallback = true;
            //    c.ExpectServerFatalAlert(AlertDescription.inappropriate_fallback);

            //    testSuite.Add(new TestCaseData(c).SetName("FallbackBad"));
            //}

            {
                TlsTestConfig c = CreateDtlsTestConfig(ProtocolVersion.DTLSv12);
                c.clientOfferVersion = ProtocolVersion.DTLSv10;

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

            /*
             * NOTE: Temporarily disabled automatic test runs because of problems getting a clean exit
             * of the DTLS server after a fatal alert. As of writing, manual runs show the correct
             * alerts being raised
             */

            //{
            //    TlsTestConfig c = CreateDtlsTestConfig(version);
            //    c.clientAuth = C.CLIENT_AUTH_INVALID_VERIFY;
            //    c.ExpectServerFatalAlert(AlertDescription.decrypt_error);

            //    testSuite.Add(new TestCaseData(c).SetName(prefix + "BadCertificateVerify"));
            //}

            //{
            //    TlsTestConfig c = CreateDtlsTestConfig(version);
            //    c.clientAuth = C.CLIENT_AUTH_INVALID_CERT;
            //    c.ExpectServerFatalAlert(AlertDescription.bad_certificate);

            //    testSuite.Add(new TestCaseData(c).SetName(prefix + "BadClientCertificate"));
            //}

            //{
            //    TlsTestConfig c = CreateDtlsTestConfig(version);
            //    c.clientAuth = C.CLIENT_AUTH_NONE;
            //    c.serverCertReq = C.SERVER_CERT_REQ_MANDATORY;
            //    c.ExpectServerFatalAlert(AlertDescription.handshake_failure);

            //    testSuite.Add(new TestCaseData(c).SetName(prefix + "BadMandatoryCertReqDeclined"));
            //}

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);

                testSuite.Add(new TestCaseData(c).SetName(prefix + "GoodDefault"));
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.serverCertReq = C.SERVER_CERT_REQ_NONE;

                testSuite.Add(new TestCaseData(c).SetName(prefix + "GoodNoCertReq"));
            }

            {
                TlsTestConfig c = CreateDtlsTestConfig(version);
                c.clientAuth = C.CLIENT_AUTH_NONE;

                testSuite.Add(new TestCaseData(c).SetName(prefix + "GoodOptionalCertReqDeclined"));
            }
        }

        private static TlsTestConfig CreateDtlsTestConfig(ProtocolVersion version)
        {
            TlsTestConfig c = new TlsTestConfig();
            c.clientMinimumVersion = ProtocolVersion.DTLSv10;
            /*
             * TODO We'd like to just set the offer version to DTLSv12, but there is a known issue with
             * overly-restrictive version checks b/w BC DTLS 1.2 client, BC DTLS 1.0 server
             */
            c.clientOfferVersion = version;
            c.serverMaximumVersion = version;
            c.serverMinimumVersion = ProtocolVersion.DTLSv10;
            return c;
        }
    }
}
