using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Tests
{
	[TestFixture]
	public class X509StoreTest
		: SimpleTest
	{
		private void certPairTest()
		{
			X509CertificateParser certParser = new X509CertificateParser();

			X509Certificate rootCert = certParser.ReadCertificate(CertPathTest.rootCertBin);
			X509Certificate interCert = certParser.ReadCertificate(CertPathTest.interCertBin);
			X509Certificate finalCert = certParser.ReadCertificate(CertPathTest.finalCertBin);

			// Testing CollectionCertStore generation from List
			X509CertificatePair pair1 = new X509CertificatePair(rootCert, interCert);

			var certList = new List<X509CertificatePair>();
			certList.Add(pair1);
			certList.Add(new X509CertificatePair(interCert, finalCert));

			var certStore = CollectionUtilities.CreateStore(certList);

			X509CertPairStoreSelector selector = new X509CertPairStoreSelector();
			X509CertStoreSelector fwSelector = new X509CertStoreSelector();

			fwSelector.SerialNumber = rootCert.SerialNumber;
			fwSelector.Subject = rootCert.IssuerDN;

			selector.ForwardSelector = fwSelector;

			var col = new List<X509CertificatePair>(certStore.EnumerateMatches(selector));

			if (col.Count != 1 || !col.Contains(pair1))
			{
				Fail("failed pair1 test");
			}

			col = new List<X509CertificatePair>(certStore.EnumerateMatches(null));

			if (col.Count != 2)
			{
				Fail("failed null test");
			}
		}

		public override void PerformTest()
		{
			X509CertificateParser certParser = new X509CertificateParser();
			X509CrlParser crlParser = new X509CrlParser();

			X509Certificate rootCert = certParser.ReadCertificate(CertPathTest.rootCertBin);
			X509Certificate interCert = certParser.ReadCertificate(CertPathTest.interCertBin);
			X509Certificate finalCert = certParser.ReadCertificate(CertPathTest.finalCertBin);
			X509Crl rootCrl = crlParser.ReadCrl(CertPathTest.rootCrlBin);
			X509Crl interCrl = crlParser.ReadCrl(CertPathTest.interCrlBin);

			// Testing CollectionCertStore generation from List
			var certList = new List<X509Certificate>();
			certList.Add(rootCert);
			certList.Add(interCert);
			certList.Add(finalCert);

			var certStore = CollectionUtilities.CreateStore(certList);

			// set default to be the same as for SUN X500 name
			X509Name.DefaultReverse = true;

			// Searching for rootCert by subjectDN

			X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
			targetConstraints.Subject = PrincipalUtilities.GetSubjectX509Principal(rootCert);
			var certs = new List<X509Certificate>(certStore.EnumerateMatches(targetConstraints));
			if (certs.Count != 1 || !certs.Contains(rootCert))
			{
				Fail("rootCert not found by subjectDN");
			}

			// Searching for rootCert by subjectDN encoded as byte
			targetConstraints = new X509CertStoreSelector();
			targetConstraints.Subject = PrincipalUtilities.GetSubjectX509Principal(rootCert);
			certs = new List<X509Certificate>(certStore.EnumerateMatches(targetConstraints));
			if (certs.Count != 1 || !certs.Contains(rootCert))
			{
				Fail("rootCert not found by encoded subjectDN");
			}

			X509Name.DefaultReverse = false;

			// Searching for rootCert by public key encoded as byte
			targetConstraints = new X509CertStoreSelector();
			targetConstraints.SubjectPublicKey =
				SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(rootCert.GetPublicKey());
			certs = new List<X509Certificate>(certStore.EnumerateMatches(targetConstraints));
			if (certs.Count != 1 || !certs.Contains(rootCert))
			{
				Fail("rootCert not found by encoded public key");
			}

			// Searching for interCert by issuerDN
			targetConstraints = new X509CertStoreSelector();
			targetConstraints.Issuer = PrincipalUtilities.GetSubjectX509Principal(rootCert);
			certs = new List<X509Certificate>(certStore.EnumerateMatches(targetConstraints));
			if (certs.Count != 2)
			{
				Fail("did not found 2 certs");
			}
			if (!certs.Contains(rootCert))
			{
				Fail("rootCert not found");
			}
			if (!certs.Contains(interCert))
			{
				Fail("interCert not found");
			}

			// Searching for rootCrl by issuerDN
			var crlList = new List<X509Crl>();
			crlList.Add(rootCrl);
			crlList.Add(interCrl);
			var crlStore = CollectionUtilities.CreateStore(crlList);

			X509CrlStoreSelector targetConstraintsCRL = new X509CrlStoreSelector();

			var issuers = new List<X509Name>();
			issuers.Add(rootCrl.IssuerDN);
			targetConstraintsCRL.Issuers = issuers;

			var crls = new List<X509Crl>(crlStore.EnumerateMatches(targetConstraintsCRL));
			if (crls.Count != 1 || !crls.Contains(rootCrl))
			{
				Fail("rootCrl not found");
			}

			// Searching for attribute certificates
			X509V2AttributeCertificate attrCert = new X509V2AttributeCertificate(AttrCertTest.attrCert);
			X509V2AttributeCertificate attrCert2 = new X509V2AttributeCertificate(AttrCertTest.certWithBaseCertificateID);

			var attrList = new List<X509V2AttributeCertificate>();
			attrList.Add(attrCert);
			attrList.Add(attrCert2);
			var attrStore = CollectionUtilities.CreateStore(attrList);

			X509AttrCertStoreSelector attrSelector = new X509AttrCertStoreSelector();
			attrSelector.Holder = attrCert.Holder;
			if (!attrSelector.Holder.Equals(attrCert.Holder))
			{
				Fail("holder get not correct");
			}
			var attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert))
			{
				Fail("attrCert not found on holder");
			}
			attrSelector.Holder = attrCert2.Holder;
			if (attrSelector.Holder.Equals(attrCert.Holder))
			{
				Fail("holder get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert2))
			{
				Fail("attrCert2 not found on holder");
			}
			attrSelector = new X509AttrCertStoreSelector();
			attrSelector.Issuer = attrCert.Issuer;
			if (!attrSelector.Issuer.Equals(attrCert.Issuer))
			{
				Fail("issuer get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert))
			{
				Fail("attrCert not found on issuer");
			}
			attrSelector.Issuer = attrCert2.Issuer;
			if (attrSelector.Issuer.Equals(attrCert.Issuer))
			{
				Fail("issuer get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert2))
			{
				Fail("attrCert2 not found on issuer");
			}
			attrSelector = new X509AttrCertStoreSelector();
			attrSelector.AttributeCert = attrCert;
			if (!attrSelector.AttributeCert.Equals(attrCert))
			{
				Fail("attrCert get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert))
			{
				Fail("attrCert not found on attrCert");
			}
			attrSelector = new X509AttrCertStoreSelector();
			attrSelector.SerialNumber = attrCert.SerialNumber;
			if (!attrSelector.SerialNumber.Equals(attrCert.SerialNumber))
			{
				Fail("serial number get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert))
			{
				Fail("attrCert not found on serial number");
			}
			attrSelector = (X509AttrCertStoreSelector)attrSelector.Clone();
			if (!attrSelector.SerialNumber.Equals(attrCert.SerialNumber))
			{
				Fail("serial number get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert))
			{
				Fail("attrCert not found on serial number");
			}

			attrSelector = new X509AttrCertStoreSelector();
			attrSelector.AttributeCertificateValid = attrCert.NotBefore;
			if (attrSelector.AttributeCertificateValid.Value != attrCert.NotBefore)
			{
				Fail("valid get not correct");
			}
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 1 || !attrs.Contains(attrCert))
			{
				Fail("attrCert not found on valid");
			}
			attrSelector = new X509AttrCertStoreSelector();
			attrSelector.AttributeCertificateValid = attrCert.NotBefore.AddMilliseconds(-100);
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 0)
			{
				Fail("attrCert found on before");
			}
			attrSelector.AttributeCertificateValid = attrCert.NotAfter.AddMilliseconds(100);
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 0)
			{
				Fail("attrCert found on after");
			}
			attrSelector.SerialNumber = BigInteger.ValueOf(10000);
			attrs = new List<X509V2AttributeCertificate>(attrStore.EnumerateMatches(attrSelector));
			if (attrs.Count != 0)
			{
				Fail("attrCert found on wrong serial number");
			}

			attrSelector.AttributeCert = null;
			attrSelector.AttributeCertificateValid = null;
			attrSelector.Holder = null;
			attrSelector.Issuer = null;
			attrSelector.SerialNumber = null;
			if (attrSelector.AttributeCert != null)
			{
				Fail("null attrCert");
			}
			if (attrSelector.AttributeCertificateValid != null)
			{
				Fail("null attrCertValid");
			}
			if (attrSelector.Holder != null)
			{
				Fail("null attrCert holder");
			}
			if (attrSelector.Issuer != null)
			{
				Fail("null attrCert issuer");
			}
			if (attrSelector.SerialNumber != null)
			{
				Fail("null attrCert serial");
			}

			certPairTest();
		}

		public override string Name
		{
			get { return "IX509Store"; }
		}

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
