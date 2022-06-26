using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;
using Org.BouncyCastle.Utilities.Test;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Tsp.Tests
{
	public class NewTspTest
	{
		private static DateTime UnixEpoch = SimpleTest.MakeUtcDateTime(1970, 1, 1, 0, 0, 0);

		[Test]
		public void TestGeneral()
		{
			string signDN = "O=Bouncy Castle, C=AU";
			AsymmetricCipherKeyPair signKP = TspTestUtil.MakeKeyPair();
			X509Certificate signCert = TspTestUtil.MakeCACertificate(signKP, signDN, signKP, signDN);

			string origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
			AsymmetricCipherKeyPair origKP = TspTestUtil.MakeKeyPair();
			AsymmetricKeyParameter privateKey = origKP.Private;

			X509Certificate cert = TspTestUtil.MakeCertificate(origKP, origDN, signKP, signDN);

			var certList = new List<X509Certificate>();
			certList.Add(cert);
			certList.Add(signCert);

			var certs = CollectionUtilities.CreateStore(certList);

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
			timeNotAvailableTest(origKP.Private, cert, certs);
			badPolicyTest(origKP.Private, cert, certs);
			tokenEncodingTest(origKP.Private, cert, certs);
			certReqTest(origKP.Private, cert, certs);
			testAccuracyZeroCerts(origKP.Private, cert, certs);
			testAccuracyWithCertsAndOrdering(origKP.Private, cert, certs);
			testNoNonse(origKP.Private, cert, certs);
			extensionTest(origKP.Private, cert, certs);
			additionalExtensionTest(origKP.Private, cert, certs);
		}

        private void additionalExtensionTest(AsymmetricKeyParameter privateKey, X509Certificate cert,
			IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);
			tsTokenGen.SetTsa(new GeneralName(new X509Name("CN=Test")));

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			X509ExtensionsGenerator extensionsGenerator = new X509ExtensionsGenerator();
			extensionsGenerator.AddExtension(X509Extensions.AuditIdentity, false, new DerUtf8String("Test"));


			TimeStampResponse tsResp = tsRespGen.GenerateGrantedResponse(request, new BigInteger("23"), new DateTimeObject( DateTime.UtcNow), "Okay", extensionsGenerator.Generate());

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

            Asn1.Cms.AttributeTable table = tsToken.SignedAttributes;

			Assert.NotNull(table[PkcsObjectIdentifiers.IdAASigningCertificate],"no signingCertificate attribute found");

			X509Extensions ext = tsToken.TimeStampInfo.TstInfo.Extensions;

			Assert.True(1 == ext.GetExtensionOids().Length);

			X509Extension left = new X509Extension(DerBoolean.False, new DerOctetString( new DerUtf8String("Test").GetEncoded()));
			Assert.True(left.Equals (ext.GetExtension(X509Extensions.AuditIdentity)));
		}

		private void extensionTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			// --- These are test case only values
			reqGen.SetReqPolicy("2.5.29.56"); 
			reqGen.AddExtension(new DerObjectIdentifier("1.3.6.1.5.5.7.1.2"), true, new DerOctetString(new byte[20]));
			// --- not for any real world purpose.

			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

			try
			{
				request.Validate(new ArrayList(), new ArrayList(), new ArrayList());
				Assert.Fail("expected exception");
			} catch(Exception ex)
            {
				Assert.True("request contains unknown algorithm" == ex.Message);
            }

			ArrayList algorithms = new ArrayList();
			algorithms.Add(TspAlgorithms.Sha1);

			try
			{
				request.Validate(algorithms, new ArrayList(), new ArrayList());
				Assert.Fail("no exception");
			}
			catch (Exception e)
			{
				Assert.IsTrue(e.Message == "request contains unknown policy");
			}

			ArrayList policies = new ArrayList();

			// Testing only do not use in real world.
			policies.Add("2.5.29.56");

			try
			{
				request.Validate(algorithms, policies, new ArrayList());
				Assert.Fail("no exception");
			}
			catch (Exception e)
			{
				Assert.IsTrue(e.Message == "request contains unknown extension");
			}

			ArrayList extensions = new ArrayList();

			// Testing only do not use in real world/
			extensions.Add("1.3.6.1.5.5.7.1.2");


			// should validate with full set
			request.Validate(algorithms, policies, extensions);

			// should validate with null policy
			request.Validate(algorithms, null, extensions);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, new BigInteger("23"), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

            Asn1.Cms.AttributeTable table = tsToken.SignedAttributes;

			Assert.NotNull(table[PkcsObjectIdentifiers.IdAASigningCertificate], "no signingCertificate attribute found");
		}

		private void testNoNonse(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				privateKey, cert, TspAlgorithms.MD5, "1.2.3");

			tsTokenGen.SetCertificates(certs);
	
			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

			ArrayList algorithms = new ArrayList();
			algorithms.Add(TspAlgorithms.Sha1);

			request.Validate(algorithms, new ArrayList(), new ArrayList());

			Assert.False(request.CertReq);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, new BigInteger("24"), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			tsToken.Validate(cert);

			tsResp.Validate(request);

			TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

			GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

			Assert.IsNull(accuracy);

			Assert.IsTrue(new BigInteger("24").Equals(tstInfo.SerialNumber));


			Assert.IsTrue("1.2.3" ==  tstInfo.Policy);

			Assert.False( tstInfo.IsOrdered);

			Assert.IsNull(tstInfo.Nonce);

			//
			// test certReq
			//
			IStore<X509Certificate> store = tsToken.GetCertificates();

			var certificates = new List<X509Certificate>(store.EnumerateMatches(null));

			Assert.IsTrue(0 == certificates.Count);
		}

		private void testAccuracyWithCertsAndOrdering(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				privateKey, cert, TspAlgorithms.MD5, "1.2.3");

			tsTokenGen.SetCertificates(certs);

			tsTokenGen.SetAccuracySeconds(1);
			tsTokenGen.SetAccuracyMillis(2);
			tsTokenGen.SetAccuracyMicros(3);

			tsTokenGen.SetOrdering(true);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();

			reqGen.SetCertReq(true);

			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);


			//
			// This is different to the Java API.
			//

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;


			tsResp.Validate(request);

			TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

			GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

			Assert.IsTrue(1 == accuracy.Seconds);
			Assert.IsTrue(2 == accuracy.Millis);
			Assert.IsTrue(3 == accuracy.Micros);

			Assert.IsTrue(new BigInteger("23").Equals(tstInfo.SerialNumber));

			Assert.IsTrue("1.2.3" == tstInfo.Policy);

			IStore<X509Certificate> store = tsToken.GetCertificates();

			var certificates = new List<X509Certificate>(store.EnumerateMatches(null));

			Assert.IsTrue(2 == certificates.Count);

		}

		private void testAccuracyZeroCerts(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			  privateKey, cert, TspAlgorithms.MD5, "1.2");

			tsTokenGen.SetCertificates(certs);

			tsTokenGen.SetAccuracySeconds(1);
			tsTokenGen.SetAccuracyMillis(2);
			tsTokenGen.SetAccuracyMicros(3);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;
	
			tsResp.Validate(request);

			TimeStampTokenInfo tstInfo = tsToken.TimeStampInfo;

			GenTimeAccuracy accuracy = tstInfo.GenTimeAccuracy;

			Assert.IsTrue(1 == accuracy.Seconds);
			Assert.IsTrue(2 == accuracy.Millis);
			Assert.IsTrue(3 == accuracy.Micros);

			Assert.IsTrue(new BigInteger("23").Equals(tstInfo.SerialNumber));

			Assert.IsTrue("1.2" == tstInfo.Policy);

			IStore<X509Certificate> store = tsToken.GetCertificates();

			var certificates = new List<X509Certificate>(store.EnumerateMatches(null));

			Assert.IsTrue(0 == certificates.Count);
		}

        private void certReqTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
			  privateKey, cert, TspAlgorithms.MD5, "1.2");

			tsTokenGen.SetCertificates(certs);
			

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			reqGen.SetCertReq(false);

			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			Assert.IsNull(tsToken.TimeStampInfo.GenTimeAccuracy);  // check for abscence of accuracy

			Assert.True("1.2".Equals( tsToken.TimeStampInfo.Policy));

			try
			{
				tsToken.Validate(cert);
			}
			catch (TspValidationException)
			{
				Assert.Fail("certReq(false) verification of token failed.");
			}

			IStore<X509Certificate> store = tsToken.GetCertificates();

			var certsColl = new List<X509Certificate>(store.EnumerateMatches(null));

			if (certsColl.Count > 0)
			{
				Assert.Fail("certReq(false) found certificates in response.");
			}
		}

		private void tokenEncodingTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.Sha1, "1.2.3.4.5.6");

			tsTokenGen.SetCertificates(certs);
		

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampResponse tsResponse = new TimeStampResponse(tsResp.GetEncoded());

			if (!Arrays.AreEqual(tsResponse.GetEncoded(), tsResp.GetEncoded())
				|| !Arrays.AreEqual(tsResponse.TimeStampToken.GetEncoded(),
				tsResp.TimeStampToken.GetEncoded()))
			{
				Assert.Fail();
			}
		}

		private void badPolicyTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				  privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);
			

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			reqGen.SetReqPolicy("1.1");
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha1, new byte[20]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed, new ArrayList());

			TimeStampResponse tsResp = tsRespGen.Generate(request, BigInteger.ValueOf(23), DateTime.UtcNow);

			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			if (tsToken != null)
			{
				Assert.Fail("badPolicy - token not null.");
			}

			PkiFailureInfo failInfo = tsResp.GetFailInfo();

			if (failInfo == null)
			{
				Assert.Fail("badPolicy - failInfo set to null.");
			}

			if (failInfo.IntValue != PkiFailureInfo.UnacceptedPolicy)
			{
				Assert.Fail("badPolicy - wrong failure info returned.");
			}


		}

		private void timeNotAvailableTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
        {
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				   privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(new DerObjectIdentifier("1.2.3.4.5"), new byte[20]);

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);			

			TimeStampResponse tsResp = null;


			//
			// This is different to the java api.
			// the java version has two calls, generateGrantedResponse and generateRejectedResponse
			// See line 726 of NewTspTest
			//

			tsResp = tsRespGen.Generate(request, new BigInteger("23"), null);
					
			tsResp = new TimeStampResponse(tsResp.GetEncoded());

			TimeStampToken tsToken = tsResp.TimeStampToken;

			if (tsToken != null)
			{
				Assert.Fail("timeNotAvailable - token not null.");
			}

			PkiFailureInfo failInfo = tsResp.GetFailInfo();

			if (failInfo == null)
			{
				Assert.Fail("timeNotAvailable - failInfo set to null.");
			}

			if (failInfo.IntValue != PkiFailureInfo.TimeNotAvailable)
			{
				Assert.Fail("timeNotAvailable - wrong failure info returned.");
			}
		}

        private void badAlgorithmTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
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

		private void incorrectHashTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
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

        private void responseValidationTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
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
			catch (TspValidationException)
			{
				// ignore
			}

			try
			{
				request = reqGen.Generate(TspAlgorithms.Sha1, new byte[22], BigInteger.ValueOf(100));

				tsResp.Validate(request);

				Assert.Fail("response validation failed on wrong digest.");
			}
			catch (TspValidationException)
			{
				// ignore
			}

			try
			{
				request = reqGen.Generate(TspAlgorithms.MD5, new byte[20], BigInteger.ValueOf(100));

				tsResp.Validate(request);

				Assert.Fail("response validation failed on wrong digest.");
			}
			catch (TspValidationException)
			{
				// ignore
			}

		}

		private void overrideAttrsTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
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
					byte[] crt = cert.GetEncoded();
					s.Write(crt, 0, crt.Length);
				}

				certHash = ((SimpleBlockResult)calc.GetResult()).Collect();
			}


			{
				Asn1DigestFactory digCalc = Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256);
				IStreamCalculator calc = digCalc.CreateCalculator();
				using (Stream s = calc.Stream)
				{
					byte[] crt = cert.GetEncoded();
					s.Write(crt, 0, crt.Length);
				}

				certHash256 = ((SimpleBlockResult)calc.GetResult()).Collect();
			}


			EssCertID essCertID = new EssCertID(certHash, issuerSerial);
			EssCertIDv2 essCertIDv2 = new EssCertIDv2(certHash256, issuerSerial);

            signerInfoGenBuilder.WithSignedAttributeGenerator(new TestAttrGen(essCertID, essCertIDv2));


			Asn1SignatureFactory sigfact = new Asn1SignatureFactory("SHA1WithRSA", privateKey);
			SignerInfoGenerator signerInfoGenerator = signerInfoGenBuilder.Build(sigfact, cert);

            TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(signerInfoGenerator,
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




		private void basicTestWithTSA(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
		{
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
				 privateKey, cert, TspAlgorithms.Sha1, "1.2");

			tsTokenGen.SetCertificates(certs);
			tsTokenGen.SetTsa(new GeneralName(new X509Name("CN=Test")));

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

		private void basicSha256Test(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
		{
			SignerInfoGenerator sInfoGenerator = makeInfoGenerator(privateKey, cert, TspAlgorithms.Sha256, null, null);
            TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
                sInfoGenerator,
                Asn1DigestFactory.Get(NistObjectIdentifiers.IdSha256), new DerObjectIdentifier("1.2"), true);

            tsTokenGen.SetCertificates(certs);

			TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
			TimeStampRequest request = reqGen.Generate(TspAlgorithms.Sha256, new byte[32], BigInteger.ValueOf(100));

			TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TspAlgorithms.Allowed);

			TimeStampResponse tsResp = tsRespGen.Generate(request, new BigInteger("23"), DateTime.UtcNow);

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
				byte[] crt = cert.GetEncoded();
				s.Write(crt, 0, crt.Length);
			}

			byte[] certHash = ((SimpleBlockResult)calc.GetResult()).Collect();

			SigningCertificateV2 sigCertV2 = SigningCertificateV2.GetInstance(table[PkcsObjectIdentifiers.IdAASigningCertificateV2].AttrValues[0]);

			Assert.IsTrue(Arrays.AreEqual(certHash, sigCertV2.GetCerts()[0].GetCertHash()));
		}

		private void resolutionTest(AsymmetricKeyParameter privateKey, X509Certificate cert,
			IStore<X509Certificate> certs, Resolution resoution, string timeString)
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

		private void basicTest(AsymmetricKeyParameter privateKey, X509Certificate cert, IStore<X509Certificate> certs)
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
				signedAttrs = new Hashtable();
			}

            string digestName = TspTestUtil.GetDigestAlgName(digestOID);
            string signatureName = digestName + "with" + TspTestUtil.GetEncryptionAlgName(
				TspTestUtil.GetEncOid(key, digestOID));

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
            private readonly EssCertID mEssCertID;
            private readonly EssCertIDv2 mEssCertIDv2;

            public TestAttrGen(EssCertID essCertID, EssCertIDv2 essCertIDv2)
            {
                this.mEssCertID = essCertID;
                this.mEssCertIDv2 = essCertIDv2;
            }

			public EssCertID EssCertID
            {
                get { return mEssCertID; }
            }

            public EssCertIDv2 EssCertIDv2
            {
                get { return mEssCertIDv2; }
            }

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
