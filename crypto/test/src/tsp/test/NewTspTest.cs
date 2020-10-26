using NUnit.Framework;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.IO;


namespace Org.BouncyCastle.Tsp.Tests
{


	public class NewTspTest
	{
		private static DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0);


		[Test]
		public void TestGeneral()
		{
			string signDN = "O=Bouncy Castle, C=AU";
			AsymmetricCipherKeyPair signKP = TspTestUtil.MakeKeyPair();
			X509Certificate signCert = TspTestUtil.MakeCACertificate(signKP, signDN, signKP, signDN);

			string origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
			AsymmetricCipherKeyPair origKP = TspTestUtil.MakeKeyPair();
			var privateKey = origKP.Private;

			var cert = TspTestUtil.MakeCertificate(origKP, origDN, signKP, signDN);

			IList certList = new ArrayList();
			certList.Add(cert);
			certList.Add(signCert);

			var certs = X509StoreFactory.Create(
				"Certificate/Collection",
				new X509CollectionStoreParameters(certList));



			basicTest(origKP.Private, cert, certs);
			resolutionTest(origKP.Private, cert, certs, Resolution.R_SECONDS, "19700101000009Z");
			resolutionTest(origKP.Private, cert, certs, Resolution.R_TENTHS_OF_SECONDS, "19700101000009.9Z");
			resolutionTest(origKP.Private, cert, certs, Resolution.R_HUNDREDTHS_OF_SECONDS, "19700101000009.99Z");
			resolutionTest(origKP.Private, cert, certs, Resolution.R_MILLISECONDS, "19700101000009.999Z");
			basicSha256Test(origKP.Private, cert, certs);
			basicTestWithTSA(origKP.Private, cert, certs);
			overrideAttrsTest(origKP.Private, cert, certs);
			responseValidationTest(origKP.Private, cert, certs);
			incorrectHashTest(origKP.Private, cert, certs);
			badAlgorithmTest(origKP.Private, cert, certs);
			//timeNotAvailableTest(origKP.Private, cert, certs);


		}

        private void timeNotAvailableTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				   privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(new DerObjectIdentifier("1.2.3.4.5"), new byte[20]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);			

			TimeStampResponse tsResp = null;

			try
			{
				tsResp = tsRespGen.Generate(request, new BigInteger("23"), null);
			}
			catch (TspException e)
			{
				Console.WriteLine();
			}

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			//TimeStampToken tsToken = tsResp.TimeStampToken;

			//if (tsToken != null)
			//{
			//	fail("timeNotAvailable - token not null.");
			//}

			//PKIFailureInfo failInfo = tsResp.getFailInfo();

			//if (failInfo == null)
			//{
			//	fail("timeNotAvailable - failInfo set to null.");
			//}

			//if (failInfo.intValue() != PKIFailureInfo.timeNotAvailable)
			//{
			//	fail("timeNotAvailable - wrong failure info returned.");
			//}
		}

        private void badAlgorithmTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				   privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(new DerObjectIdentifier("1.2.3.4.5"), new byte[21]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			if (tsToken != null)
			{
				Assert.Fail("badAlgorithm - token not null.");
			}

			PkiFailureInfo failInfo = tsResp.GetFailInfo();

			if (failInfo == null)
			{
				Assert.Fail("badAlgorithm - failInfo set to null.");
			}

			if (failInfo.IntValue != PkiFailureInfo.BadAlg)
			{
				Assert.Fail("badAlgorithm - wrong failure info returned.");
			}
		}

		private void incorrectHashTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				  privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[16]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			Assert.IsNull(tsToken,"incorrect hash -- token not null");

			PkiFailureInfo failInfo = tsResp.GetFailInfo();
			if (failInfo == null)
            {
				Assert.Fail("incorrectHash - failInfo set to null.");
            }

			if (failInfo.IntValue != PkiFailureInfo.BadDataFormat)
            {
				Assert.Fail("incorrectHash - wrong failure info returned.");
			}

		}

        private void responseValidationTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.MD5, "1.2");

			tsTokenGen.SetCertificates(certs);
			

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);


			try
			{
				request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(101));

				tsResp.Validate(request);

				Assert.Fail("response validation failed on invalid nonce.");
			}
			catch (TspValidationException e)
			{
				// ignore
			}

			try
			{
				request = reqGen.Generate(TspAlgorithms.Sha1, new byte[22], BigInteger.ValueOf(100));

				tsResp.Validate(request);

				Assert.Fail("response validation failed on wrong digest.");
			}
			catch (TspValidationException e)
			{
				// ignore
			}

			try
			{
				request = reqGen.Generate(TspAlgorithms.MD5, new byte[20], BigInteger.ValueOf(100));

				tsResp.Validate(request);

				Assert.Fail("response validation failed on wrong digest.");
			}
			catch (TspValidationException e)
			{
				// ignore
			}

		}

		private void overrideAttrsTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
		{
			SignerInfoGeneratorBuilder signerInfoGenBuilder = new SignerInfoGeneratorBuilder();

			IssuerSerial issuerSerial = new IssuerSerial(
				new GeneralNames(
					new GeneralName(
						X509CertificateStructure.GetInstance(cert.GetEncoded()).Issuer)),
				new DerInteger(cert.SerialNumber));

			byte[] certHash256;
			byte[] certHash;

			{
				Asn1DigestFactory digCalc = Asn1DigestFactory.Get(OiwObjectIdentifiers.IdSha1);
				IStreamCalculator calc = digCalc.CreateCalculator();
				using (Stream s = calc.Stream)
				{
					var crt = cert.GetEncoded();
					s.Write(crt, 0, crt.Length);
				}

				certHash = ((SimpleBlockResult)calc.GetResult()).Collect();
			}


			{
				Asn1DigestFactory digCalc = Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256);
				IStreamCalculator calc = digCalc.CreateCalculator();
				using (Stream s = calc.Stream)
				{
					var crt = cert.GetEncoded();
					s.Write(crt, 0, crt.Length);
				}

				certHash256 = ((SimpleBlockResult)calc.GetResult()).Collect();
			}


			EssCertID essCertid = new EssCertID(certHash, issuerSerial);
			EssCertIDv2 essCertidV2 = new EssCertIDv2(certHash256, issuerSerial);

			signerInfoGenBuilder.WithSignedAttributeGenerator(new TestAttrGen()
			{
				EssCertID = essCertid,
				EssCertIDv2 = essCertidV2
			});


			Asn1SignatureFactory sigfact = new Asn1SignatureFactory("SHA1WithRSA", privateKey);
			SignerInfoGenerator
				 signerInfoGenerator = signerInfoGenBuilder.Build(sigfact, cert);

			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				signerInfoGenerator,
				Asn1DigestFactory.Get(OiwObjectIdentifiers.IdSha1), new DerObjectIdentifier("1.2"), true);


			tsTokenGen.SetCertificates(certs);
		

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

			Asn1.Cms.AttributeTable table = tsToken.SignedAttributes;

			Assert.NotNull( table[PkcsObjectIdentifiers.IdAASigningCertificate], "no signingCertificate attribute found");
			Assert.NotNull( table[PkcsObjectIdentifiers.IdAASigningCertificateV2], "no signingCertificateV2 attribute found");

			SigningCertificate sigCert = SigningCertificate.GetInstance(table[PkcsObjectIdentifiers.IdAASigningCertificate].AttrValues[0]);

			Assert.IsTrue(cert.CertificateStructure.Issuer.Equals( sigCert.GetCerts()[0].IssuerSerial.Issuer.GetNames()[0].Name));
			Assert.IsTrue(cert.CertificateStructure.SerialNumber.Value.Equals( sigCert.GetCerts()[0].IssuerSerial.Serial.Value));
			Assert.IsTrue(Arrays.AreEqual(certHash, sigCert.GetCerts()[0].GetCertHash()));

			SigningCertificate sigCertV2 = SigningCertificate.GetInstance(table[PkcsObjectIdentifiers.IdAASigningCertificateV2].AttrValues[0]);

			Assert.IsTrue(cert.CertificateStructure.Issuer.Equals(sigCertV2.GetCerts()[0].IssuerSerial.Issuer.GetNames()[0].Name));
			Assert.IsTrue(cert.CertificateStructure.SerialNumber.Value.Equals(sigCertV2.GetCerts()[0].IssuerSerial.Serial.Value));
			Assert.IsTrue(Arrays.AreEqual(certHash256, sigCertV2.GetCerts()[0].GetCertHash()));

		}




		private void basicTestWithTSA(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);
			tsTokenGen.SetTsa(new Asn1.X509.GeneralName(new X509Name("CN=Test")));

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

			Asn1.Cms.AttributeTable table = tsToken.SignedAttributes;

			Assert.IsNotNull(table[PkcsObjectIdentifiers.IdAASigningCertificate], "no signingCertificate attribute found");

		}

		private void basicSha256Test(AsymmetricKeyParameter privateKey, X509Certificate cert, IX509Store certs)
		{
			var sInfoGenerator = makeInfoGenerator(privateKey, cert, TspAlgorithms.Sha256, null, null);
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				sInfoGenerator,
				Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256), new DerObjectIdentifier("1.2"), true);


			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, new BigInteger("23"), DateTime.Now);

			Assert.AreEqual((int)PkiStatus.Granted, tsResp.Status);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

			Asn1.Cms.AttributeTable table = tsToken.SignedAttributes;

			Assert.NotNull(table[PkcsObjectIdentifiers.IdAASigningCertificateV2]);

			Asn1DigestFactory digCalc = Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256);
			IStreamCalculator calc = digCalc.CreateCalculator();
			using (Stream s = calc.Stream)
			{
				var crt = cert.GetEncoded();
				s.Write(crt, 0, crt.Length);
			}

			byte[] certHash = ((SimpleBlockResult)calc.GetResult()).Collect();

			SigningCertificateV2 sigCertV2 = SigningCertificateV2.GetInstance(table[PkcsObjectIdentifiers.IdAASigningCertificateV2].AttrValues[0]);

			Assert.IsTrue(Arrays.AreEqual(certHash, sigCertV2.GetCerts()[0].GetCertHash()));
		}


		private void resolutionTest(AsymmetricKeyParameter privateKey, X509.X509Certificate cert, IX509Store certs, Resolution resoution, string timeString)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			 privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.Resolution = resoution;
			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), UnixEpoch.AddMilliseconds(9999));

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			// This done instead of relying on string comparison.
			Assert.AreEqual(timeString, tsToken.TimeStampInfo.TstInfo.GenTime.TimeString);

			tsResp = tsRespGen.Generate(request, new BigInteger("23"), UnixEpoch.AddMilliseconds(9000));
			tsToken = tsResp.TimeStampToken;
			Assert.AreEqual("19700101000009Z", tsToken.TimeStampInfo.TstInfo.GenTime.TimeString);

			if ((int)resoution > (int)Resolution.R_HUNDREDTHS_OF_SECONDS)
			{
				tsResp = tsRespGen.Generate(request, new BigInteger("23"), UnixEpoch.AddMilliseconds(9990));
				tsToken = tsResp.TimeStampToken;
				Assert.AreEqual("19700101000009.99Z", tsToken.TimeStampInfo.TstInfo.GenTime.TimeString);
			}

			if ((int)resoution > (int)Resolution.R_TENTHS_OF_SECONDS)
			{
				tsResp = tsRespGen.Generate(request, new BigInteger("23"), UnixEpoch.AddMilliseconds(9900));
				tsToken = tsResp.TimeStampToken;
				Assert.AreEqual("19700101000009.9Z", tsToken.TimeStampInfo.TstInfo.GenTime.TimeString);
			}


		}

		private void basicTest(AsymmetricKeyParameter privateKey, X509.X509Certificate cert, IX509Store certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

			Asn1.Cms.AttributeTable table = tsToken.SignedAttributes;

			Assert.IsNotNull(table[PkcsObjectIdentifiers.IdAASigningCertificate], "no signingCertificate attribute found");


		}

		internal static SignerInfoGenerator makeInfoGenerator(
		 AsymmetricKeyParameter key,
		 X509Certificate cert,
		 string digestOID,

		 Asn1.Cms.AttributeTable signedAttr,
		 Asn1.Cms.AttributeTable unsignedAttr)
		{


			TspUtil.ValidateCertificate(cert);

			//
			// Add the ESSCertID attribute
			//
			IDictionary signedAttrs;
			if (signedAttr != null)
			{
				signedAttrs = signedAttr.ToDictionary();
			}
			else
			{
				signedAttrs = Platform.CreateHashtable();
			}



			string digestName = CmsSignedHelper.Instance.GetDigestAlgName(digestOID);
			string signatureName = digestName + "with" + CmsSignedHelper.Instance.GetEncryptionAlgName(CmsSignedHelper.Instance.GetEncOid(key, digestOID));

			Asn1SignatureFactory sigfact = new Asn1SignatureFactory(signatureName, key);
			return new SignerInfoGeneratorBuilder()
			 .WithSignedAttributeGenerator(
				new DefaultSignedAttributeTableGenerator(
					new Asn1.Cms.AttributeTable(signedAttrs)))
			  .WithUnsignedAttributeGenerator(
				new SimpleAttributeTableGenerator(unsignedAttr))
				.Build(sigfact, cert);
		}




		private class TestAttrGen : CmsAttributeTableGenerator
		{

			public EssCertID EssCertID { get; set; }

			public EssCertIDv2 EssCertIDv2 { get; set; }

			public Asn1.Cms.AttributeTable GetAttributes(IDictionary parameters)
			{
				CmsAttributeTableGenerator attrGen = new DefaultSignedAttributeTableGenerator();

				Asn1.Cms.AttributeTable table = attrGen.GetAttributes(parameters);
				table = table.Add(PkcsObjectIdentifiers.IdAASigningCertificate, new SigningCertificate(EssCertID));
				table = table.Add(PkcsObjectIdentifiers.IdAASigningCertificateV2, new SigningCertificateV2(new EssCertIDv2[] { EssCertIDv2 }));

				return table;
			}
		}

	}

}
