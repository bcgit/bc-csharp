using NUnit.Framework;

using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
	public class Pkcs12Test
		: SimpleTest
	{
		private static byte[] pkcs12 = Base64.Decode(
			  "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"
			+ "AgFkAAA=");

		public override void PerformTest()
        {
            byte[] pfxEncoding1 = ImplTest(pkcs12);
            byte[] pfxEncoding2 = ImplTest(pfxEncoding1);

            //
            // comparison test
            //
            if (!Arrays.AreEqual(pfxEncoding1, pfxEncoding2))
            {
                Fail("failed comparison test");
            }
        }

        private byte[] ImplTest(byte[] pkcs12)
		{
			Pfx pfx = Pfx.GetInstance(pkcs12);
			ContentInfo info = pfx.AuthSafe;
			MacData macData = pfx.MacData;

            Asn1OctetString content = Asn1OctetString.GetInstance(info.Content);
			AuthenticatedSafe authSafe = AuthenticatedSafe.GetInstance(content.GetOctets());
			ContentInfo[] c = authSafe.GetContentInfo();

			//
			// private key section
			//
			if (!c[0].ContentType.Equals(PkcsObjectIdentifiers.Data))
			{
				Fail("Failed comparison data test");
			}

            Asn1OctetString authSafeContent = Asn1OctetString.GetInstance(c[0].Content);
            Asn1Sequence seq = Asn1Sequence.GetInstance(authSafeContent.GetOctets());

            SafeBag b = SafeBag.GetInstance(seq[0]);
			if (!b.BagID.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
			{
				Fail("Failed comparison shroudedKeyBag test");
			}

			EncryptedPrivateKeyInfo epki = EncryptedPrivateKeyInfo.GetInstance(b.BagValueEncodable);

			epki = new EncryptedPrivateKeyInfo(epki.EncryptionAlgorithm, epki.GetEncryptedData());

			b = new SafeBag(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag, epki, b.BagAttributes);

			byte[] contentOctets = new DerSequence(b).GetEncoded();

			c[0] = new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(contentOctets));

			//
			// certificates
			//
			if (!c[1].ContentType.Equals(PkcsObjectIdentifiers.EncryptedData))
			{
				Fail("Failed comparison encryptedData test");
			}

			EncryptedData eData = EncryptedData.GetInstance(c[1].Content);

			c[1] = new ContentInfo(PkcsObjectIdentifiers.EncryptedData, eData);

			//
			// create an octet stream to represent the BER encoding of authSafe
			//
			authSafe = new AuthenticatedSafe(c);

            contentOctets = authSafe.GetEncoded();

            info = new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(contentOctets));

			pfx = new Pfx(info, macData);

			return pfx.GetEncoded();
		}

		public override string Name => "Pkcs12";

		[Test]
		public void TestFunction()
		{
			string resultText = Perform().ToString();

			Assert.AreEqual(Name + ": Okay", resultText);
		}
	}
}
