using System.Collections.Generic;
using System.IO;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Cms.Tests
{
    [TestFixture]
    [Parallelizable(ParallelScope.All)]
    public class MiscDataStreamTest
	{
		private const string TestMessage = "Hello World!";

		private const string OrigDN = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
		private static AsymmetricCipherKeyPair origKP;
		private static X509Certificate origCert;

        private static AsymmetricCipherKeyPair origDsaKP;
        private static X509Certificate origDsaCert;

        private const string ReciDN = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
        //private static AsymmetricCipherKeyPair reciKP;
        //private static X509Certificate reciCert;

        private const string SignDN = "O=Bouncy Castle, C=AU";
        private static AsymmetricCipherKeyPair signKP;
        private static X509Certificate signCert;

		private static X509Crl signCrl;
		private static X509Crl origCrl;

        private static AsymmetricCipherKeyPair OrigKP => CmsTestUtil.InitKP(ref origKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair OrigDsaKP =>
            CmsTestUtil.InitKP(ref origDsaKP, CmsTestUtil.MakeDsaKeyPair);

        //private static AsymmetricCipherKeyPair ReciKP => CmsTestUtil.InitKP(ref reciKP, CmsTestUtil.MakeKeyPair);

        private static AsymmetricCipherKeyPair SignKP => CmsTestUtil.InitKP(ref signKP, CmsTestUtil.MakeKeyPair);

        private static X509Certificate OrigCert => CmsTestUtil.InitCertificate(ref origCert,
            () => CmsTestUtil.MakeCertificate(OrigKP, OrigDN, SignKP, SignDN));

        private static X509Certificate OrigDsaCert => CmsTestUtil.InitCertificate(ref origDsaCert,
            () => CmsTestUtil.MakeCertificate(OrigDsaKP, OrigDN, SignKP, SignDN));

        //private static X509Certificate ReciCert => CmsTestUtil.InitCertificate(ref reciCert,
        //    () => CmsTestUtil.MakeCertificate(ReciKP, ReciDN, SignKP, SignDN));

        private static X509Certificate SignCert => CmsTestUtil.InitCertificate(ref signCert,
            () => CmsTestUtil.MakeCertificate(SignKP, SignDN, SignKP, SignDN));

        private static X509Crl OrigCrl => CmsTestUtil.InitCrl(ref origCrl, () => CmsTestUtil.MakeCrl(OrigKP));

        private static X509Crl SignCrl => CmsTestUtil.InitCrl(ref signCrl, () => CmsTestUtil.MakeCrl(SignKP));

        private void VerifySignatures(CmsSignedDataParser sp, byte[] contentDigest)
		{
			IStore<X509Certificate> certStore = sp.GetCertificates();
			SignerInformationStore signers = sp.GetSignerInfos();

			foreach (SignerInformation signer in signers.GetSigners())
			{
				var certCollection = certStore.EnumerateMatches(signer.SignerID);

				var certEnum = certCollection.GetEnumerator();

				certEnum.MoveNext();
				X509Certificate	cert = certEnum.Current;

				Assert.IsTrue(signer.Verify(cert));

				if (contentDigest != null)
				{
					Assert.IsTrue(Arrays.AreEqual(contentDigest, signer.GetContentDigest()));
				}
			}
		}

		private void VerifySignatures(
			CmsSignedDataParser sp)
		{
			VerifySignatures(sp, null);
		}

		//private void VerifyEncodedData(MemoryStream bOut)
		//{
		//	using (var sp = new CmsSignedDataParser(bOut.ToArray()))
		//	{
		//		sp.GetSignedContent().Drain();

		//		VerifySignatures(sp);
		//	}
		//}

		private void CheckSigParseable(byte[] sig)
		{
			using (var sp = new CmsSignedDataParser(sig))
			{
                sp.Version.ToString();
                CmsTypedStream sc = sp.GetSignedContent();
                if (sc != null)
                {
                    sc.Drain();
                }
                sp.GetAttributeCertificates();
                sp.GetCertificates();
                sp.GetCrls();
                sp.GetSignerInfos();
            }
        }

		[Test]
		public void TestSha1WithRsa()
		{
			var certList = new List<X509Certificate>();
			certList.Add(OrigCert);
			certList.Add(SignCert);

			var crlList = new List<X509Crl>();
			crlList.Add(SignCrl);
			crlList.Add(OrigCrl);

			var x509Certs = CollectionUtilities.CreateStore(certList);
			var x509Crls = CollectionUtilities.CreateStore(crlList);

			CmsSignedDataStreamGenerator gen = new CmsSignedDataStreamGenerator();

			gen.AddSigner(OrigKP.Private, OrigCert, CmsSignedDataStreamGenerator.DigestSha1);

			gen.AddCertificates(x509Certs);
			gen.AddCrls(x509Crls);

			MemoryStream bOut = new MemoryStream();
			Stream sigOut = gen.Open(bOut);

			CmsCompressedDataStreamGenerator cGen = new CmsCompressedDataStreamGenerator();

			Stream cOut = cGen.Open(sigOut, CmsCompressedDataStreamGenerator.ZLib);

			byte[] testBytes = Encoding.ASCII.GetBytes(TestMessage);
			cOut.Write(testBytes, 0, testBytes.Length);

			cOut.Close();

			sigOut.Close();

			CheckSigParseable(bOut.ToArray());

			// generate compressed stream
			MemoryStream cDataOut = new MemoryStream();
		    
			cOut = cGen.Open(cDataOut, CmsCompressedDataStreamGenerator.ZLib);

			cOut.Write(testBytes, 0, testBytes.Length);

			cOut.Close();

			CmsSignedDataParser sp = new CmsSignedDataParser(
				new CmsTypedStream(new MemoryStream(cDataOut.ToArray(), false)), bOut.ToArray());

			sp.GetSignedContent().Drain();

            byte[] cDataOutBytes = cDataOut.ToArray();

            // compute expected content digest
            byte[] hash = DigestUtilities.CalculateDigest("SHA1", cDataOutBytes);

            VerifySignatures(sp, hash);
		}
	}
}
