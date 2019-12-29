﻿using System;
using System.Collections;
using System.IO;
using System.Reflection;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.Test;
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

		private static readonly IDictionary certs = new Hashtable();
		private static readonly IDictionary crls = new Hashtable();

        private static readonly ISet noPolicies = new HashSet();
        private static readonly ISet anyPolicy = new HashSet();
        private static readonly ISet nistTestPolicy1 = new HashSet();
        private static readonly ISet nistTestPolicy2 = new HashSet();
        private static readonly ISet nistTestPolicy3 = new HashSet();
        private static readonly ISet nistTestPolicy1And2 = new HashSet();

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
			ISet		policies,
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
			ISet policies)
		{
			ISet trustedSet = new HashSet();
			trustedSet.Add(GetTrustAnchor(trustAnchor));

			IList x509Certs = new ArrayList();
			IList x509Crls = new ArrayList();
			X509Certificate endCert = LoadCert(certs[certs.Length - 1]);

			for (int i = 0; i != certs.Length - 1; i++)
			{
				x509Certs.Add(LoadCert(certs[i]));
			}

			x509Certs.Add(endCert);

			PkixCertPath certPath = new PkixCertPath(x509Certs);

			for (int i = 0; i != crls.Length; i++)
			{
				x509Crls.Add(LoadCrl(crls[i]));
			}

			IX509Store x509CertStore = X509StoreFactory.Create(
				"Certificate/Collection",
				new X509CollectionStoreParameters(x509Certs));
			IX509Store x509CrlStore = X509StoreFactory.Create(
				"CRL/Collection",
				new X509CollectionStoreParameters(x509Crls));

            PkixCertPathValidator validator = new PkixCertPathValidator();
			PkixParameters parameters = new PkixParameters(trustedSet);

			parameters.AddStore(x509CertStore);
			parameters.AddStore(x509CrlStore);
			parameters.IsRevocationEnabled = true;

			if (policies != null)
			{
				parameters.IsExplicitPolicyRequired = true;
				parameters.SetInitialPolicies(policies);
			}

			// Perform validation as of this date since test certs expired
			parameters.Date = new DateTimeObject(DateTime.Parse("1/1/2011"));

			return validator.Validate(certPath, parameters);
        }

        private PkixCertPathBuilderResult DoBuilderTest(
            string trustAnchor,
            string[] certs,
            string[] crls,
            ISet initialPolicies,
            bool policyMappingInhibited,
            bool anyPolicyInhibited)
        {
            ISet trustedSet = new HashSet();
            trustedSet.Add(GetTrustAnchor(trustAnchor));

            IList x509Certs = new ArrayList();
            IList x509Crls = new ArrayList();
            X509Certificate endCert = LoadCert(certs[certs.Length - 1]);

            for (int i = 0; i != certs.Length - 1; i++)
            {
                x509Certs.Add(LoadCert(certs[i]));
            }

            x509Certs.Add(endCert);

            for (int i = 0; i != crls.Length; i++)
            {
                x509Crls.Add(LoadCrl(crls[i]));
            }

            IX509Store x509CertStore = X509StoreFactory.Create(
                "Certificate/Collection",
                new X509CollectionStoreParameters(x509Certs));
            IX509Store x509CrlStore = X509StoreFactory.Create(
                "CRL/Collection",
                new X509CollectionStoreParameters(x509Crls));

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

            builderParams.AddStore(x509CertStore);
            builderParams.AddStore(x509CrlStore);

            // Perform validation as of this date since test certs expired
            builderParams.Date = new DateTimeObject(DateTime.Parse("1/1/2011"));

            try
            {
                return (PkixCertPathBuilderResult)builder.Build(builderParams);
            }
            catch (PkixCertPathBuilderException e)
            {
                throw e.InnerException;
            }
        }

        private X509Certificate LoadCert(string certName)
		{
			X509Certificate cert = (X509Certificate)certs[certName];
			if (null != cert)
				return cert;

            Stream fs = null;

			try
			{
				fs = SimpleTest.GetTestDataAsStream("PKITS.certs." + certName + ".crt");
				cert = new X509CertificateParser().ReadCertificate(fs);
				certs[certName] = cert;
				return cert;
			}
			catch (Exception e)
			{
				throw new InvalidOperationException("exception loading certificate " + certName + ": " + e);
			}
			finally
			{
				fs.Close();
			}
		}

		private X509Crl LoadCrl(string crlName)
		{
			X509Crl crl = (X509Crl)crls[crlName];
			if (null != crl)
				return crl;

            Stream fs = null;

			try
			{
				fs = SimpleTest.GetTestDataAsStream("PKITS.crls." + crlName + ".crl");
				crl = new X509CrlParser().ReadCrl(fs);
				crls[crlName] = crl;
				return crl;
			}
			catch (Exception)
			{
				throw new InvalidOperationException("exception loading CRL: " + crlName);
			}
			finally
			{
				fs.Close();
			}
		}

        private TrustAnchor GetTrustAnchor(string trustAnchorName)
		{
			X509Certificate cert = LoadCert(trustAnchorName);
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
