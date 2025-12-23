using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary> SHA224 HMac Test, test vectors from RFC</summary>
    [TestFixture]
    public class Sha224HMacTest
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
            "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
            "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
            "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
            "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
            "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c",
            "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
            "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
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
            HMac hmac = new HMac(new Sha224Digest());
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
            HMac hmac = new HMac(new Sha224Digest());
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
