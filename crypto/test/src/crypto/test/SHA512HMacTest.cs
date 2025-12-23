using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary> SHA512 HMac Test, test vectors from RFC</summary>
    [TestFixture]
    public class Sha512HMacTest
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
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b",
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
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
            HMac hmac = new HMac(new Sha512Digest());
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
            HMac hmac = new HMac(new Sha512Digest());
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
