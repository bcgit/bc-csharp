using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Tests
{
    /// <summary>SM3 HMac test vectors, using the standard RFC 2202 / RFC 4231 key/message inputs.</summary>
    /// <remarks>
    /// SM3 is a 256-bit digest, so HMAC-SM3 produces a full 32-byte output; these vectors guard against the output
    /// length being truncated.
    /// </remarks>
    [TestFixture]
    public class SM3HMacTest
    {
        private static readonly string[] Keys = {
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "4a656665",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0102030405060708090a0b0c0d0e0f10111213141516171819",
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        };

        private static readonly string[] Digests = {
            "12d66c84b4a40ad8035c263e419bd43c7e52fb438b930eba0c94e34cdb9b63f3",
            "2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882",
            "7bfeba1b1518329f73aad171e89009fc41d43b66de11e779b5615bfbf0b85973",
            "b57c79be03472aeb8cada581dea332cb2ba83d19cb1b052dd07194def75fb8cd",
            "47541fc981b3457ab94e71b31911c73762ef466f5fe84411467f90686d97120a",
            "c794651f5455f80546855f744ff50146d5286e1cb677d5088c059cd8b03bb9ce",
            "0888924905d64874be20dc784b57f2cf9ea375905339075c5af90418b4bf8705",
        };

        private static readonly string[] Messages = {
            "Hi There",
            "what do ya want for nothing?",
            "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            "Test With Truncation",
            "Test Using Larger Than Block-Size Key - Hash Key First",
            "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        };

        [Test]
        public void Basic()
        {
            HMac hmac = new HMac(new SM3Digest());
            Assert.AreEqual(32, hmac.GetMacSize());

            byte[] resBuf = new byte[hmac.GetMacSize()];
            for (int i = 0; i < Messages.Length; ++i)
            {
                string message = Messages[i];

                byte[] m;
                if (message.StartsWith("0x"))
                {
                    m = Hex.DecodeStrict(message, 2, message.Length - 2);
                }
                else
                {
                    m = Strings.ToUtf8ByteArray(message);
                }

                hmac.Init(new KeyParameter(Hex.Decode(Keys[i])));
                hmac.BlockUpdate(m, 0, m.Length);
                hmac.DoFinal(resBuf, 0);

                Assert.That(Arrays.AreEqual(Hex.DecodeStrict(Digests[i]), resBuf));
            }
        }
    }
}
