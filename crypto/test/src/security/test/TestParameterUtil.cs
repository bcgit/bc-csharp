using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security.Tests
{
	[TestFixture]
	public class TestParameterUtilities
	{
		[Test]
		public void TestCreateKeyParameter()
		{
			SecureRandom random = new SecureRandom();

			doTestCreateKeyParameter("AES", NistObjectIdentifiers.IdAes128Cbc,
				128, typeof(KeyParameter), random);
			doTestCreateKeyParameter("DES", OiwObjectIdentifiers.DesCbc,
				64, typeof(DesParameters), random);
			doTestCreateKeyParameter("DESEDE", PkcsObjectIdentifiers.DesEde3Cbc,
				192, typeof(DesEdeParameters), random);
			doTestCreateKeyParameter("RC2", PkcsObjectIdentifiers.RC2Cbc,
				128, typeof(RC2Parameters), random);
		}

        [Test]
        public void TestGetCipherParameters()
        {
            var aes128Ccm = ParameterUtilities.GetCipherParameters(
                NistObjectIdentifiers.IdAes128Ccm,
                new KeyParameter(new byte[16]),
                new CcmParameters(new byte[12], 16).ToAsn1Object());
            Assert.IsInstanceOf(typeof(AeadParameters), aes128Ccm);

            var aes192Ccm = ParameterUtilities.GetCipherParameters(
                NistObjectIdentifiers.IdAes192Ccm,
                new KeyParameter(new byte[24]),
                new CcmParameters(new byte[12], 16).ToAsn1Object());
            Assert.IsInstanceOf(typeof(AeadParameters), aes192Ccm);

            var aes256Ccm = ParameterUtilities.GetCipherParameters(
                NistObjectIdentifiers.IdAes256Ccm,
                new KeyParameter(new byte[32]),
                new CcmParameters(new byte[12], 16).ToAsn1Object());
            Assert.IsInstanceOf(typeof(AeadParameters), aes256Ccm);

            var aes128Gcm = ParameterUtilities.GetCipherParameters(
                NistObjectIdentifiers.IdAes128Gcm,
                new KeyParameter(new byte[16]),
                new GcmParameters(new byte[12], 16).ToAsn1Object());
            Assert.IsInstanceOf(typeof(AeadParameters), aes128Gcm);

            var aes192Gcm = ParameterUtilities.GetCipherParameters(
                NistObjectIdentifiers.IdAes192Gcm,
                new KeyParameter(new byte[24]),
                new GcmParameters(new byte[12], 16).ToAsn1Object());
            Assert.IsInstanceOf(typeof(AeadParameters), aes192Gcm);

            var aes256Gcm = ParameterUtilities.GetCipherParameters(
				NistObjectIdentifiers.IdAes256Gcm,
				new KeyParameter(new byte[32]),
				new GcmParameters(new byte[12], 16).ToAsn1Object());
            Assert.IsInstanceOf(typeof(AeadParameters), aes256Gcm);
        }

        private void doTestCreateKeyParameter(
			string				algorithm,
			DerObjectIdentifier	oid,
			int					keyBits,
			Type				expectedType,
			SecureRandom		random)
		{
			int keyLength = keyBits / 8;
			byte[] bytes = new byte[keyLength];
			random.NextBytes(bytes);

			KeyParameter key;

			key = ParameterUtilities.CreateKeyParameter(algorithm, bytes);
			checkKeyParameter(key, expectedType, bytes);

			key = ParameterUtilities.CreateKeyParameter(oid, bytes);
			checkKeyParameter(key, expectedType, bytes);

			bytes = new byte[keyLength * 2];
			random.NextBytes(bytes);

			int offset = random.Next(1, keyLength);
			byte[] expected = new byte[keyLength];
			Array.Copy(bytes, offset, expected, 0, keyLength);

			key = ParameterUtilities.CreateKeyParameter(algorithm, bytes, offset, keyLength);
			checkKeyParameter(key, expectedType, expected);

			key = ParameterUtilities.CreateKeyParameter(oid, bytes, offset, keyLength);
			checkKeyParameter(key, expectedType, expected);
		}

		private void checkKeyParameter(
			KeyParameter	key,
			Type			expectedType,
			byte[]			expectedBytes)
		{
			Assert.IsTrue(expectedType.IsInstanceOfType(key));
			Assert.IsTrue(Arrays.AreEqual(expectedBytes, key.GetKey()));
		}
	}
}
