using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary> SHA1 HMac Test, test vectors from RFC 2202</summary>
    [TestFixture]
    public class Sha1HMacTest
    {
        private static readonly string[] Keys =
        {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4a656665",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };

        private static readonly string[] Digests =
        {
            "b617318655057264e28bc0b6fb378c8ef146be00",
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
            "aa4ae5e15272d00e95705637ce8a3b55ed402112",
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
        };

        private static readonly string[] Messages =
        {
            "Hi There",
            "what do ya want for nothing?",
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "Test With Truncation",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        };

        [Test]
        public void TestBasic()
        {
            HMac hmac = new HMac(new Sha1Digest());
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
            HMac hmac = new HMac(new Sha1Digest());
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
