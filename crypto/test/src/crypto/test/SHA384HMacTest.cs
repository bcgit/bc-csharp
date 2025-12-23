using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary> SHA384 HMac Test, test vectors from RFC</summary>
    [TestFixture]
    public class Sha384HMacTest
    {
        private static readonly string[] Keys =
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4a656665",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };

        private static readonly string[] Digests =
        {
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
            "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
            "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
            "3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea",
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
        };

        private static readonly string[] Messages =
        {
            "Hi There",
            "what do ya want for nothing?",
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "Test With Truncation",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
        };

        [Test]
        public void TestBasic()
        {
            HMac hmac = new HMac(new Sha384Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];

            for (int i = 0; i < Messages.Length; i++)
            {
                var message = Messages[i];
                var key = Keys[i];
                var digest = Digests[i];

                byte[] m = GetMessageBytes(message);

                hmac.Init(new KeyParameter(Hex.Decode(key)));
                hmac.BlockUpdate(m, 0, m.Length);
                hmac.DoFinal(resBuf, 0);

                Assert.True(Arrays.AreEqual(resBuf, Hex.Decode(digest)), "Vector " + i + " failed");
            }
        }

        [Test]
        public void TestReset()
        {
            HMac hmac = new HMac(new Sha384Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];

            int i = 0;
            var message = Messages[i];
            var key = Keys[i];
            var digest = Digests[i];

            byte[] m = GetMessageBytes(message);

            hmac.Init(new KeyParameter(Hex.Decode(key)));
            hmac.BlockUpdate(m, 0, m.Length);
            hmac.DoFinal(resBuf, 0);
            hmac.Reset();
            hmac.BlockUpdate(m, 0, m.Length);
            hmac.DoFinal(resBuf, 0);

            Assert.True(Arrays.AreEqual(resBuf, Hex.Decode(digest)), "Reset with vector " + i + " failed");
        }

        private static byte[] GetMessageBytes(string message)
        {
            return message.StartsWith("0x")
                ? Hex.Decode(message.Substring(2))
                : Encoding.ASCII.GetBytes(message);
        }
    }
}
