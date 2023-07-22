using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nsri;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Tests
{
    /// <remarks>Basic test class for the ARIA cipher vectors from FIPS-197</remarks>
    [TestFixture]
    public class AriaTest
        : BaseBlockCipherTest
    {
        internal static readonly string[] cipherTests =
        {
            "128",
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "d718fbd6ab644c739da95f3be6451778",
            "192",
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "00112233445566778899aabbccddeeff",
            "26449c1805dbe7aa25a468ce263a9e79",
            "256",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "f92bd7c79fb72e2f2b8f80c1972d24fc"
        };

        public AriaTest()
            : base("ARIA")
        {
        }

        [Test]
        public void TestCiphers()
        {
            for (int i = 0; i != cipherTests.Length; i += 4)
            {
                DoCipherTest(int.Parse(cipherTests[i]),
                    Hex.Decode(cipherTests[i + 1]),
                    Hex.Decode(cipherTests[i + 2]),
                    Hex.Decode(cipherTests[i + 3]));
            }
        }

        [Test]
		public void TestOids()
		{
			string[] oids = {
                NsriObjectIdentifiers.id_aria128_ecb.Id,
                NsriObjectIdentifiers.id_aria128_cbc.Id,
                NsriObjectIdentifiers.id_aria128_ofb.Id,
                NsriObjectIdentifiers.id_aria128_cfb.Id,
                NsriObjectIdentifiers.id_aria192_ecb.Id,
                NsriObjectIdentifiers.id_aria192_cbc.Id,
                NsriObjectIdentifiers.id_aria192_ofb.Id,
                NsriObjectIdentifiers.id_aria192_cfb.Id,
                NsriObjectIdentifiers.id_aria256_ecb.Id,
                NsriObjectIdentifiers.id_aria256_cbc.Id,
                NsriObjectIdentifiers.id_aria256_ofb.Id,
                NsriObjectIdentifiers.id_aria256_cfb.Id
            };

			string[] names = {
                "ARIA/ECB/PKCS7Padding",
                "ARIA/CBC/PKCS7Padding",
                "ARIA/OFB/NoPadding",
                "ARIA/CFB/NoPadding",
                "ARIA/ECB/PKCS7Padding",
                "ARIA/CBC/PKCS7Padding",
                "ARIA/OFB/NoPadding",
                "ARIA/CFB/NoPadding",
                "ARIA/ECB/PKCS7Padding",
                "ARIA/CBC/PKCS7Padding",
                "ARIA/OFB/NoPadding",
                "ARIA/CFB/NoPadding"
			};

			oidTest(oids, names, 4);
		}

        [Test]
        public void TestWrap()
        {
            byte[] kek1 = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] in1 = Hex.Decode("00112233445566778899aabbccddeeff");
            byte[] out1 = Hex.Decode("a93f148d4909d85f1aae656909879275ae597b3acf9d60db");

            wrapTest(1, "ARIAWrap", kek1, in1, out1);
        }

        [Test]
        public void TestWrapRfc3211()
        {
            byte[] kek2 = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] in2 = Hex.Decode("00112233445566778899aabbccddeeff");
            byte[] out2 = Hex.Decode("9b2d3cac0acf9d4bde7c1bdb0313fbef931f025acc77bf57d3d1cabc88b514d0");

            wrapTest(2, "ARIARFC3211WRAP", kek2, kek2, FixedSecureRandom.From(Hex.Decode("9688df2af1b7b1ac9688df2a")), in2, out2);
        }

        [Test]
        public void TestWrapRfc5649()
        {
            byte[] kek3 = Hex.Decode("000102030405060708090a0b0c0d0e0f");
            byte[] in3 = Hex.Decode("00112233445566778899aabbccddeeff");
            byte[] out3 = Hex.Decode("ac0e22699a036ced63adeb75f4946f82dc98ad8af43b24d5");

            wrapTest(3, "ARIAWrapPad", kek3, in3, out3);
        }

        [Test]
		public void TestWrapOids()
		{
			string[] wrapOids =
			{
                NsriObjectIdentifiers.id_aria128_kw.Id,
                NsriObjectIdentifiers.id_aria192_kw.Id,
                NsriObjectIdentifiers.id_aria256_kw.Id
			};

			wrapOidTest(wrapOids, "ARIAWrap");
		}

        [Test]
        public void TestWrapPadOids()
        {
            string[] wrapPadOids =
            {
                NsriObjectIdentifiers.id_aria128_kwp.Id,
                NsriObjectIdentifiers.id_aria192_kwp.Id,
                NsriObjectIdentifiers.id_aria256_kwp.Id
            };

            wrapOidTest(wrapPadOids, "ARIAWrapPad");
        }

        private void DoCipherTest(int strength, byte[] keyBytes, byte[] input, byte[] output)
        {
            KeyParameter key = ParameterUtilities.CreateKeyParameter("ARIA", keyBytes);

			IBufferedCipher inCipher = CipherUtilities.GetCipher("ARIA/ECB/NoPadding");
			IBufferedCipher outCipher = CipherUtilities.GetCipher("ARIA/ECB/NoPadding");

			try
			{
				outCipher.Init(true, key);
			}
			catch (Exception e)
			{
				Fail("ARIA failed initialisation - " + e, e);
			}

			try
			{
				inCipher.Init(false, key);
			}
			catch (Exception e)
			{
				Fail("ARIA failed initialisation - " + e, e);
			}

			//
			// encryption pass
			//
			MemoryStream bOut = new MemoryStream();

			CipherStream cOut = new CipherStream(bOut, null, outCipher);

			try
			{
				for (int i = 0; i != input.Length / 2; i++)
				{
					cOut.WriteByte(input[i]);
				}
				cOut.Write(input, input.Length / 2, input.Length - input.Length / 2);
				cOut.Close();
			}
			catch (IOException e)
			{
				Fail("ARIA failed encryption - " + e, e);
			}

			byte[] bytes = bOut.ToArray();

			if (!AreEqual(bytes, output))
			{
				Fail("ARIA failed encryption - expected "
					+ Hex.ToHexString(output) + " got "
					+ Hex.ToHexString(bytes));
			}

			//
			// decryption pass
			//
			MemoryStream bIn = new MemoryStream(bytes, false);

			CipherStream cIn = new CipherStream(bIn, inCipher, null);

			try
			{
//				DataInputStream dIn = new DataInputStream(cIn);
				BinaryReader dIn = new BinaryReader(cIn);

				bytes = new byte[input.Length];

				for (int i = 0; i != input.Length / 2; i++)
				{
//					bytes[i] = (byte)dIn.read();
					bytes[i] = dIn.ReadByte();
				}

				int remaining = bytes.Length - input.Length / 2;
//				dIn.readFully(bytes, input.Length / 2, remaining);
				byte[] extra = dIn.ReadBytes(remaining);
				if (extra.Length < remaining)
					throw new EndOfStreamException();
				extra.CopyTo(bytes, input.Length / 2);
			}
			catch (Exception e)
			{
				Fail("ARIA failed encryption - " + e, e);
			}

			if (!AreEqual(bytes, input))
			{
				Fail("ARIA failed decryption - expected "
					+ Hex.ToHexString(input) + " got "
					+ Hex.ToHexString(bytes));
			}
		}

		[Test]
		public void TestEax()
		{
            byte[] K = Hex.Decode("233952DEE4D5ED5F9B9C6D6FF80FF478");
            byte[] N = Hex.Decode("62EC67F9C3A4A407FCB2A8C49031A8B3");
            byte[] P = Hex.Decode("68656c6c6f20776f726c642121");
            byte[] C = Hex.Decode("85fe63d6cfb872d2420e65425c074dfad6fe752e03");

			KeyParameter key = ParameterUtilities.CreateKeyParameter("ARIA", K);
			IBufferedCipher inCipher = CipherUtilities.GetCipher("ARIA/EAX/NoPadding");
			IBufferedCipher outCipher = CipherUtilities.GetCipher("ARIA/EAX/NoPadding");

			inCipher.Init(true, new ParametersWithIV(key, N));

			byte[] enc = inCipher.DoFinal(P);
			if (!AreEqual(enc, C))
			{
				Fail("ciphertext doesn't match in EAX");
			}

			outCipher.Init(false, new ParametersWithIV(key, N));

			byte[] dec = outCipher.DoFinal(C);
			if (!AreEqual(dec, P))
			{
				Fail("plaintext doesn't match in EAX");
			}

			try
			{
				inCipher = CipherUtilities.GetCipher("ARIA/EAX/PKCS5Padding");

				Fail("bad padding missed in EAX");
			}
			catch (SecurityUtilityException)
			{
				// expected
			}
		}

		[Test]
		public void TestCcm()
		{
            byte[] K = Hex.Decode("404142434445464748494a4b4c4d4e4f");
            byte[] N = Hex.Decode("10111213141516");
            byte[] P = Hex.Decode("68656c6c6f20776f726c642121");
            byte[] C = Hex.Decode("0af625ff69cd9dbe65fae181d654717eb7a0263bcd");

			KeyParameter key = ParameterUtilities.CreateKeyParameter("ARIA", K);

			IBufferedCipher inCipher = CipherUtilities.GetCipher("ARIA/CCM/NoPadding");
			IBufferedCipher outCipher = CipherUtilities.GetCipher("ARIA/CCM/NoPadding");

			inCipher.Init(true, new ParametersWithIV(key, N));

			byte[] enc = inCipher.DoFinal(P);
			if (!AreEqual(enc, C))
			{
				Fail("ciphertext doesn't match in CCM");
			}

			outCipher.Init(false, new ParametersWithIV(key, N));

			byte[] dec = outCipher.DoFinal(C);
			if (!AreEqual(dec, P))
			{
				Fail("plaintext doesn't match in CCM");
			}

			try
			{
				inCipher = CipherUtilities.GetCipher("ARIA/CCM/PKCS5Padding");

				Fail("bad padding missed in CCM");
			}
			catch (SecurityUtilityException)
			{
				// expected
			}
		}

		[Test]
		public void TestGcm()
		{
            // Test Case 15 from McGrew/Viega
            byte[] K = Hex.Decode(
                  "feffe9928665731c6d6a8f9467308308"
                + "feffe9928665731c6d6a8f9467308308");
            byte[] P = Hex.Decode(
                  "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b391aafd255");
            byte[] N = Hex.Decode("cafebabefacedbaddecaf888");
            string T = "c8f245c8619ca9ba7d6d9545e7f48214";
            byte[] C = Hex.Decode(
                  "c3aa0e01a4f8b5dfdb25d0f1c78c275e516114080e2be7a7f7bffd4504b19a8552f80ad5b55f3d911725489629996d398d5ed6f077e22924c5b8ebe20a219693"
                + T);

			KeyParameter key = ParameterUtilities.CreateKeyParameter("ARIA", K);
			IBufferedCipher inCipher = CipherUtilities.GetCipher("ARIA/GCM/NoPadding");
			IBufferedCipher outCipher = CipherUtilities.GetCipher("ARIA/GCM/NoPadding");

			inCipher.Init(true, new ParametersWithIV(key, N));

			byte[] enc = inCipher.DoFinal(P);
			if (!AreEqual(enc, C))
			{
				Fail("ciphertext doesn't match in GCM");
			}

			outCipher.Init(false, new ParametersWithIV(key, N));

			byte[] dec = outCipher.DoFinal(C);
			if (!AreEqual(dec, P))
			{
				Fail("plaintext doesn't match in GCM");
			}

			try
			{
				inCipher = CipherUtilities.GetCipher("ARIA/GCM/PKCS5Padding");

				Fail("bad padding missed in GCM");
			}
			catch (SecurityUtilityException)
			{
				// expected
			}
		}

		[Test]
		public void TestOcb()
		{
            byte[] K = Hex.Decode("000102030405060708090A0B0C0D0E0F");
            byte[] P = Hex.Decode("000102030405060708090A0B0C0D0E0F");
            byte[] N = Hex.Decode("000102030405060708090A0B");
            string T = "0027ce4f3aaeec75";
            byte[] C = Hex.Decode("7bcae9eac9f1f54704a630e309099a87f53a1c1559de1b3b" + T);

            KeyParameter key = ParameterUtilities.CreateKeyParameter("ARIA", K);
            IBufferedCipher inCipher = CipherUtilities.GetCipher("ARIA/OCB/NoPadding");
            IBufferedCipher outCipher = CipherUtilities.GetCipher("ARIA/OCB/NoPadding");

			inCipher.Init(true, new ParametersWithIV(key, N));

            byte[] enc = inCipher.DoFinal(P);
			if (!AreEqual(enc, C))
			{
				Fail("ciphertext doesn't match in OCB");
			}

			outCipher.Init(false, new ParametersWithIV(key, N));

			byte[] dec = outCipher.DoFinal(C);
			if (!AreEqual(dec, P))
			{
				Fail("plaintext doesn't match in OCB");
			}

			try
			{
                inCipher = CipherUtilities.GetCipher("ARIA/OCB/PKCS5Padding");

				Fail("bad padding missed in OCB");
			}
			catch (SecurityUtilityException)
			{
				// expected
			}
		}

        public override void PerformTest()
        {
            TestCiphers();
            TestWrap();
            TestWrapRfc3211();
            TestWrapRfc5649();
            TestOids();
            TestWrapOids();
            TestWrapPadOids();
			TestEax();
			TestCcm();
			TestGcm();
            TestOcb();
        }
    }
}
