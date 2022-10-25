using System;
using System.Collections.Generic;
#if NET5_0_OR_GREATER
using System.Runtime.Versioning;
#endif
using System.Security.Cryptography;
using SystemX509 = System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Security.Tests
{
	[TestFixture]
    public class TestDotNetUtilities
	{
//#if NET5_0_OR_GREATER
#if NET6_0_OR_GREATER
        [SupportedOSPlatform("windows")]
#endif
        [Test]
		public void TestRsaInterop()
		{
			for (int i = 0; i < 100; ++i)
			{
				RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(512);
				RSAParameters rp = rsa.ExportParameters(true);
				AsymmetricCipherKeyPair kp = DotNetUtilities.GetRsaKeyPair(rp);

				DotNetUtilities.ToRSA((RsaKeyParameters)kp.Public);
				// TODO This method appears to not work for private keys (when no CRT info)
				//DotNetUtilities.ToRSA((RsaKeyParameters)kp.Private);
				DotNetUtilities.ToRSA((RsaPrivateCrtKeyParameters)kp.Private);
			}
		}

		[Test]
		public void TestX509CertificateConversion()
		{
			BigInteger DSAParaG = new BigInteger(Base64.Decode("AL0fxOTq10OHFbCf8YldyGembqEu08EDVzxyLL29Zn/t4It661YNol1rnhPIs+cirw+yf9zeCe+KL1IbZ/qIMZM="));
			BigInteger DSAParaP = new BigInteger(Base64.Decode("AM2b/UeQA+ovv3dL05wlDHEKJ+qhnJBsRT5OB9WuyRC830G79y0R8wuq8jyIYWCYcTn1TeqVPWqiTv6oAoiEeOs="));
			BigInteger DSAParaQ = new BigInteger(Base64.Decode("AIlJT7mcKL6SUBMmvm24zX1EvjNx"));
			BigInteger DSAPublicY = new BigInteger(Base64.Decode("TtWy2GuT9yGBWOHi1/EpCDa/bWJCk2+yAdr56rAcqP0eHGkMnA9s9GJD2nGU8sFjNHm55swpn6JQb8q0agrCfw=="));
			BigInteger DsaPrivateX = new BigInteger(Base64.Decode("MMpBAxNlv7eYfxLTZ2BItJeD31A="));

			DsaParameters para = new DsaParameters(DSAParaP, DSAParaQ, DSAParaG);
			DsaPrivateKeyParameters dsaPriv = new DsaPrivateKeyParameters(DsaPrivateX, para);
			DsaPublicKeyParameters dsaPub = new DsaPublicKeyParameters(DSAPublicY, para);

			var attrs = new Dictionary<DerObjectIdentifier, string>();
			attrs[X509Name.C] = "AU";
			attrs[X509Name.O] = "The Legion of the Bouncy Castle";
			attrs[X509Name.L] = "Melbourne";
			attrs[X509Name.ST] = "Victoria";
			attrs[X509Name.E] = "feedback-crypto@bouncycastle.org";

			var ord = new List<DerObjectIdentifier>(attrs.Keys);

			X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

			certGen.SetSerialNumber(BigInteger.One);

			certGen.SetIssuerDN(new X509Name(ord, attrs));
			certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1));
			certGen.SetNotAfter(DateTime.UtcNow.AddDays(1));
			certGen.SetSubjectDN(new X509Name(ord, attrs));
			certGen.SetPublicKey(dsaPub);

            X509Certificate cert = certGen.Generate(new Asn1SignatureFactory("SHA1WITHDSA", dsaPriv, null));

            cert.CheckValidity();
			cert.Verify(dsaPub);

			SystemX509.X509Certificate dotNetCert = DotNetUtilities.ToX509Certificate(cert);

			X509Certificate certCopy = DotNetUtilities.FromX509Certificate(dotNetCert);

			Assert.AreEqual(cert, certCopy);

			certCopy.CheckValidity();
			certCopy.Verify(dsaPub);
		}
	}
}
