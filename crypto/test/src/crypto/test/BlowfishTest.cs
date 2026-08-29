using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
	/// <remarks>Blowfish tester - vectors from http://www.counterpane.com/vectors.txt</remarks>
    [TestFixture]
    public class BlowfishTest
		: CipherTest
    {
        public override string Name
        {
			get { return "Blowfish"; }
        }

        internal static SimpleTest[] tests = new SimpleTest[]{
            new BlockCipherVectorTest(0, new BlowfishEngine(), new KeyParameter(Hex.Decode("0000000000000000")), "0000000000000000", "4EF997456198DD78"),
            new BlockCipherVectorTest(1, new BlowfishEngine(), new KeyParameter(Hex.Decode("FFFFFFFFFFFFFFFF")), "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"),
            new BlockCipherVectorTest(2, new BlowfishEngine(), new KeyParameter(Hex.Decode("3000000000000000")), "1000000000000001", "7D856F9A613063F2"),
            new BlockCipherVectorTest(3, new BlowfishEngine(), new KeyParameter(Hex.Decode("1111111111111111")), "1111111111111111", "2466DD878B963C9D"),
            new BlockCipherVectorTest(4, new BlowfishEngine(), new KeyParameter(Hex.Decode("0123456789ABCDEF")), "1111111111111111", "61F9C3802281B096"),
            new BlockCipherVectorTest(5, new BlowfishEngine(), new KeyParameter(Hex.Decode("FEDCBA9876543210")), "0123456789ABCDEF", "0ACEAB0FC6A0A28D"),
            new BlockCipherVectorTest(6, new BlowfishEngine(), new KeyParameter(Hex.Decode("7CA110454A1A6E57")), "01A1D6D039776742", "59C68245EB05282B"),
            new BlockCipherVectorTest(7, new BlowfishEngine(), new KeyParameter(Hex.Decode("0131D9619DC1376E")), "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"),

            // with BlowfishParameters
            new BlockCipherVectorTest(10, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("0000000000000000")), "0000000000000000", "4EF997456198DD78"),
            new BlockCipherVectorTest(11, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("FFFFFFFFFFFFFFFF")), "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A"),
            new BlockCipherVectorTest(12, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("3000000000000000")), "1000000000000001", "7D856F9A613063F2"),
            new BlockCipherVectorTest(13, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("1111111111111111")), "1111111111111111", "2466DD878B963C9D"),
            new BlockCipherVectorTest(14, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("0123456789ABCDEF")), "1111111111111111", "61F9C3802281B096"),
            new BlockCipherVectorTest(15, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("FEDCBA9876543210")), "0123456789ABCDEF", "0ACEAB0FC6A0A28D"),
            new BlockCipherVectorTest(16, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("7CA110454A1A6E57")), "01A1D6D039776742", "59C68245EB05282B"),
            new BlockCipherVectorTest(17, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("0131D9619DC1376E")), "5CD54CA83DEF57DA", "B1B8CC0B250F09A0"),

            // with BlowfishParameters and extended keys
            new BlockCipherVectorTest(20, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), extendedKey: true), "0000000000000000", "4ef997456198dd78"),
            new BlockCipherVectorTest(21, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), extendedKey: true), "0000000000000000", "4ef997456198dd78"),
            new BlockCipherVectorTest(22, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), extendedKey: true), "ffffffffffffffff", "51866fd5b85ecb8a"),
            new BlockCipherVectorTest(23, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), extendedKey: true), "ffffffffffffffff", "51866fd5b85ecb8a"),
            new BlockCipherVectorTest(24, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"), extendedKey: true), "1111111111111111", "2466dd878b963c9d"),
            new BlockCipherVectorTest(25, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"), extendedKey: true), "1111111111111111", "2466dd878b963c9d"),
            new BlockCipherVectorTest(26, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), extendedKey: true), "1000000000000001", "6252d3fc90256722"),
            new BlockCipherVectorTest(27, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("30000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), extendedKey: true), "1000000000000001", "6252d3fc90256722"),
            new BlockCipherVectorTest(28, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("4f8afc23a1daac522510982b41c9186081b2a00537e193d85d004013ce520cc77aeb3c7822668c425adf7a9af977ad0c380f471229dcc73478d6a560ce3bc730df05e975a6d06d4e"), extendedKey: true), "63038f81aff43d3e", "88ccd0c218b35b0b"),
            new BlockCipherVectorTest(29, new BlowfishEngine(), new BlowfishParameters(Hex.Decode("4f8afc23a1daac522510982b41c9186081b2a00537e193d85d004013ce520cc77aeb3c7822668c425adf7a9af977ad0c380f471229dcc73478d6a560ce3bc730df05e975a6d06d4e9be8ca0e"), extendedKey: true), "63038f81aff43d3e", "88ccd0c218b35b0b"),
        };

        public BlowfishTest()
			: base(tests, new BlowfishEngine(), new KeyParameter(new byte[16]))
		{
        }

		[Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            BlowfishEngine blowfish = new BlowfishEngine();

            // key range check
            try
            {
                blowfish.Init(true, new KeyParameter(new byte[1]));
                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.AreEqual("key length must be in range 32 to 448 bits", e.Message);
            }

            try
            {
                blowfish.Init(true, new KeyParameter(new byte[59]));
                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.AreEqual("key length must be in range 32 to 448 bits", e.Message);
            }

            // key range check -- new BlowfishParameters
            try
            {
                blowfish.Init(true, new BlowfishParameters(new byte[1]));
                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.AreEqual("key length must be in range 32 to 448 bits", e.Message);
            }

            try
            {
                blowfish.Init(true, new BlowfishParameters(new byte[59]));
                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                Assert.AreEqual("key length must be in range 32 to 448 bits", e.Message);
            }

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
