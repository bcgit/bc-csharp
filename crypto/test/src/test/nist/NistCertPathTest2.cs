using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Tests.Nist
{
    /**
     * NIST CertPath test data for RFC 3280
     */
    [TestFixture]
    public class NistCertPathTest2
    {
        private static readonly string ANY_POLICY = "2.5.29.32.0";
        private static readonly string NIST_TEST_POLICY_1 = "2.16.840.1.101.3.2.1.48.1";
        private static readonly string NIST_TEST_POLICY_2 = "2.16.840.1.101.3.2.1.48.2";
        private static readonly string NIST_TEST_POLICY_3 = "2.16.840.1.101.3.2.1.48.3";

        private static readonly ISet<string> noPolicies = new HashSet<string>();
        private static readonly ISet<string> anyPolicy = new HashSet<string>();
        private static readonly ISet<string> nistTestPolicy1 = new HashSet<string>();
        private static readonly ISet<string> nistTestPolicy2 = new HashSet<string>();
        private static readonly ISet<string> nistTestPolicy3 = new HashSet<string>();
        private static readonly ISet<string> nistTestPolicy1And2 = new HashSet<string>();

        static NistCertPathTest2()
		{
			anyPolicy.Add(ANY_POLICY);

			nistTestPolicy1.Add(NIST_TEST_POLICY_1);
			nistTestPolicy2.Add(NIST_TEST_POLICY_2);
			nistTestPolicy3.Add(NIST_TEST_POLICY_3);
			nistTestPolicy1And2.Add(NIST_TEST_POLICY_1);
			nistTestPolicy1And2.Add(NIST_TEST_POLICY_2);
		}

        // 4.13
		[Test]
        public void TestValidDNnameConstraintsTest1()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest1EE", "nameConstraintsDN1CACert" },
                new string[] { "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" });
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest2()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest2EE", "nameConstraintsDN1CACert"},
                new string[]{"nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest3()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest3EE", "nameConstraintsDN1CACert"},
                new string[]{"nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject alternative name failed.");
        }

 		[Test]
       public void TestValidDNnameConstraintsTest4()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest4EE", "nameConstraintsDN1CACert" },
                new string[] { "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" });
        }

		[Test]
        public void TestValidDNnameConstraintsTest5()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest5EE", "nameConstraintsDN2CACert" },
                new string[] { "nameConstraintsDN2CACRL", "TrustAnchorRootCRL" });
        }

		[Test]
        public void TestValidDNnameConstraintsTest6()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest6EE", "nameConstraintsDN3CACert" },
                new string[] { "nameConstraintsDN3CACRL", "TrustAnchorRootCRL" });
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest7()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest7EE", "nameConstraintsDN3CACert"},
                new string[]{"nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest8()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest8EE", "nameConstraintsDN4CACert"},
                new string[]{"nameConstraintsDN4CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest9()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest9EE", "nameConstraintsDN4CACert"},
                new string[]{"nameConstraintsDN4CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest10()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest10EE", "nameConstraintsDN5CACert"},
                new string[]{"nameConstraintsDN5CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestValidDNnameConstraintsTest11()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest11EE", "nameConstraintsDN5CACert" },
                new string[] { "nameConstraintsDN5CACRL", "TrustAnchorRootCRL" });
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest12()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest10EE", "nameConstraintsDN5CACert"},
                new string[]{"nameConstraintsDN5CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest13()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest13EE", "nameConstraintsDN1subCA2Cert", "nameConstraintsDN1CACert"},
                new string[]{"nameConstraintsDN1subCA2CRL", "nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestValidDNnameConstraintsTest14()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest14EE", "nameConstraintsDN1subCA2Cert", "nameConstraintsDN1CACert" },
                new string[] { "nameConstraintsDN1subCA2CRL", "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" });
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest15()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest15EE", "nameConstraintsDN3subCA1Cert", "nameConstraintsDN3CACert"},
                new string[]{"nameConstraintsDN3subCA1CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest16()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest16EE", "nameConstraintsDN3subCA1Cert", "nameConstraintsDN3CACert"},
                new string[]{"nameConstraintsDN3subCA1CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

		[Test]
        public void TestInvalidDNnameConstraintsTest17()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest17EE", "nameConstraintsDN3subCA2Cert", "nameConstraintsDN3CACert"},
                new string[]{"nameConstraintsDN3subCA2CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL"},
                0,
                "Subtree check for certificate subject failed.");
        }

 		[Test]
        public void TestValidDNnameConstraintsTest18()
        {
            DoTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest18EE", "nameConstraintsDN3subCA2Cert", "nameConstraintsDN3CACert" },
                new string[] { "nameConstraintsDN3subCA2CRL", "nameConstraintsDN3CACRL", "TrustAnchorRootCRL" });
        }

 		[Test]
        public void TestValidDNnameConstraintsTest19()
        {
            DoBuilderTest("TrustAnchorRootCertificate",
                new string[] { "ValidDNnameConstraintsTest19EE", "nameConstraintsDN1SelfIssuedCACert", "nameConstraintsDN1CACert" },
                new string[] { "nameConstraintsDN1CACRL", "TrustAnchorRootCRL" },
                null, false, false);
        }

 		[Test]
        public void TestInvalidDNnameConstraintsTest20()
        {
            DoExceptionTest("TrustAnchorRootCertificate",
                new string[]{"InvalidDNnameConstraintsTest20EE", "nameConstraintsDN1CACert"},
                new string[]{"nameConstraintsDN1CACRL", "TrustAnchorRootCRL"},
                0,
                "CertPath for CRL signer failed to validate.");   // due to a subtree failure
        }

		private void DoExceptionTest(
			string		trustAnchor,
			string[]	certs,
			string[]	crls,
			int			index,
			string		message)
		{
			try
			{
				DoTest(trustAnchor, certs, crls);

				Assert.Fail("path accepted when should be rejected");
			}
			catch (PkixCertPathValidatorException e)
			{
				Assert.AreEqual(index, e.Index);
				Assert.AreEqual(message, e.Message);
			}
		}

		private void DoExceptionTest(
			string		trustAnchor,
			string[]	certs,
			string[]	crls,
			ISet<string> policies,
			int			index,
			string		message)
		{
			try
			{
				DoTest(trustAnchor, certs, crls, policies);

				Assert.Fail("path accepted when should be rejected");
			}
			catch (PkixCertPathValidatorException e)
			{
				Assert.AreEqual(index, e.Index);
				Assert.AreEqual(message, e.Message);
			}
		}

		private void DoExceptionTest(
			string		trustAnchor,
			string[]	certs,
			string[]	crls,
			int			index,
			string		mesStart,
			string		mesEnd)
		{
			try
			{
				DoTest(trustAnchor, certs, crls);

				Assert.Fail("path accepted when should be rejected");
			}
			catch (PkixCertPathValidatorException e)
			{
				Assert.AreEqual(index, e.Index);
				Assert.IsTrue(e.Message.StartsWith(mesStart));
				Assert.IsTrue(e.Message.EndsWith(mesEnd));
			}
		}

		private PkixCertPathValidatorResult DoTest(
			string trustAnchor,
			string[] certs,
			string[] crls)
		{
			return DoTest(trustAnchor, certs, crls, null);
		}

		private PkixCertPathValidatorResult DoTest(
			string trustAnchor,
			string[] certs,
			string[] crls,
			ISet<string> policies)
		{
			var trustedSet = new HashSet<TrustAnchor>();
			trustedSet.Add(GetTrustAnchor(trustAnchor));

			var x509Certs = new List<X509Certificate>();
			var x509Crls = new List<X509Crl>();
			X509Certificate endCert = PkitsTestData.GetCertificate(certs[certs.Length - 1]);

			for (int i = 0; i != certs.Length - 1; i++)
			{
				x509Certs.Add(PkitsTestData.GetCertificate(certs[i]));
			}

			x509Certs.Add(endCert);

			PkixCertPath certPath = new PkixCertPath(x509Certs);

			for (int i = 0; i != crls.Length; i++)
			{
				x509Crls.Add(PkitsTestData.GetCrl(crls[i]));
			}

            var x509CertStore = CollectionUtilities.CreateStore(x509Certs);
			var x509CrlStore = CollectionUtilities.CreateStore(x509Crls);

            PkixCertPathValidator validator = new PkixCertPathValidator();
			PkixParameters parameters = new PkixParameters(trustedSet);

			parameters.AddStoreCert(x509CertStore);
			parameters.AddStoreCrl(x509CrlStore);
			parameters.IsRevocationEnabled = true;

			if (policies != null)
			{
				parameters.IsExplicitPolicyRequired = true;
				parameters.SetInitialPolicies(policies);
			}

			// Perform validation as of this date since test certs expired
			parameters.Date = DateTime.Parse("1/1/2011");

			return validator.Validate(certPath, parameters);
        }

        private PkixCertPathBuilderResult DoBuilderTest(
            string trustAnchor,
            string[] certs,
            string[] crls,
            ISet<string> initialPolicies,
            bool policyMappingInhibited,
            bool anyPolicyInhibited)
        {
            var trustedSet = new HashSet<TrustAnchor>();
            trustedSet.Add(GetTrustAnchor(trustAnchor));

            var x509Certs = new List<X509Certificate>();
            var x509Crls = new List<X509Crl>();
            X509Certificate endCert = PkitsTestData.GetCertificate(certs[certs.Length - 1]);

            for (int i = 0; i != certs.Length - 1; i++)
            {
                x509Certs.Add(PkitsTestData.GetCertificate(certs[i]));
            }

            x509Certs.Add(endCert);

            for (int i = 0; i != crls.Length; i++)
            {
                x509Crls.Add(PkitsTestData.GetCrl(crls[i]));
            }

            var x509CertStore = CollectionUtilities.CreateStore(x509Certs);
            var x509CrlStore = CollectionUtilities.CreateStore(x509Crls);

            PkixCertPathBuilder builder = new PkixCertPathBuilder();

            X509CertStoreSelector endSelector = new X509CertStoreSelector();

            endSelector.Certificate = endCert;

            PkixBuilderParameters builderParams = new PkixBuilderParameters(trustedSet, endSelector);

            if (initialPolicies != null)
            {
                builderParams.SetInitialPolicies(initialPolicies);
                builderParams.IsExplicitPolicyRequired = true;
            }
            if (policyMappingInhibited)
            {
                builderParams.IsPolicyMappingInhibited = policyMappingInhibited;
            }
            if (anyPolicyInhibited)
            {
                builderParams.IsAnyPolicyInhibited = anyPolicyInhibited;
            }

            builderParams.AddStoreCert(x509CertStore);
            builderParams.AddStoreCrl(x509CrlStore);

            // Perform validation as of this date since test certs expired
            builderParams.Date = DateTime.Parse("1/1/2011");

            try
            {
                return (PkixCertPathBuilderResult)builder.Build(builderParams);
            }
            catch (PkixCertPathBuilderException e)
            {
                throw e.InnerException;
            }
        }

        private TrustAnchor GetTrustAnchor(string trustAnchorName)
		{
			X509Certificate cert = PkitsTestData.GetCertificate(trustAnchorName);
			Asn1OctetString extBytes = cert.GetExtensionValue(X509Extensions.NameConstraints);

			if (extBytes != null)
			{
				Asn1Encodable extValue = X509ExtensionUtilities.FromExtensionValue(extBytes);

				return new TrustAnchor(cert, extValue.GetDerEncoded());
			}

			return new TrustAnchor(cert, null);
		}
    }
}
