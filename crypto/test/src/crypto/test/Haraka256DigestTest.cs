using System;
using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class Haraka256DigestTest : SimpleTest
    {
        public override string Name
        {
            get { return "Haraka 256"; }
        }

        public void TestKnownVector()
        {
            byte[] input = new byte[32];
            for (int t = 0; t < input.Length; t++)
            {
                input[t] = (byte)t;
            }

            // From Appendix B, Haraka-256 v2, https://eprint.iacr.org/2016/098.pdf
            byte[] expected256 = Hex.Decode("8027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c");

            Haraka256Digest haraka = new Haraka256Digest();
            haraka.Update(input, 0, input.Length);
            byte[] output = new byte[haraka.GetDigestSize()];
            haraka.DoFinal(output, 0);
            Assert.IsTrue(Arrays.AreEqual(expected256, output));
        }


        public void TestInputTooShort()
        {
            try
            {
                Haraka256Digest haraka = new Haraka256Digest();
                byte[] input = new byte[31];
                haraka.Update(input, 0, input.Length);
                haraka.DoFinal(null, 0);
                Assert.Fail("fail on input not 32 bytes.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "input must be exactly 32 bytes"));
            }
        }

        public void TestInputTooLong()
        {
            try
            {
                Haraka256Digest haraka = new Haraka256Digest();
                byte[] input = new byte[33];
                haraka.Update(input, 0, input.Length);
                haraka.DoFinal(null, 0);
                Assert.Fail("fail on input not 32 bytes.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "total input cannot be more than 32 bytes"));
            }
        }

        public void TestOutput()
        {

            //
            // Buffer too short.
            //
            try
            {
                Haraka256Digest harakaCipher = new Haraka256Digest();
                byte[] input = new byte[32];
                harakaCipher.Update(input, 0, input.Length);
                byte[] output = new byte[31];
                harakaCipher.DoFinal(output, 0);
                Assert.Fail("Output too short for digest result.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "output too short to receive digest"));
            }

            //
            // Offset puts end past length of buffer.
            //
            try
            {
                Haraka256Digest harakaCipher = new Haraka256Digest();
                byte[] input = new byte[32];
                harakaCipher.Update(input, 0, input.Length);
                byte[] output = new byte[48];
                harakaCipher.DoFinal(output, 17);
                Assert.Fail("Output too short for digest result.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "output too short to receive digest"));
            }

            //
            // Offset output..
            //
            try
            {
                byte[] input = new byte[32];
                for (int t = 0; t < input.Length; t++)
                {
                    input[t] = (byte)t;
                }

                byte[] expected256 = Hex.Decode("000000008027ccb87949774b78d0545fb72bf70c695c2a0923cbd47bba1159efbf2b2c1c");

                Haraka256Digest harakaCipher = new Haraka256Digest();
                harakaCipher.Update(input, 0, input.Length);
                byte[] output = new byte[harakaCipher.GetDigestSize() + 4];
                harakaCipher.DoFinal(output, 4);
                Assert.IsTrue(Arrays.AreEqual(expected256, output));
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "output too short to receive digest"));
            }
        }

        void TestMonty()
        {
            int c = 0;
            string[][] vectors = new string[][]{new string[]
            {
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
                "e78599d7163ab58f1c90f0171c6fc4e852eb4b8cc29a4af63194fd9977c1de84"
            },
            new string[]{
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "c4cebda63c00c4cd312f36ea92afd4b0f6048507c5b367326ef9d8fdd2d5c09a"
            }
            };

            for (int i = 0; i != vectors.Length; i++)
            {
                //
                // 1000 rounds of digest application, where alternative outputs are copied over alternate halves of the input.
                //
                string[] vector = vectors[i];

                byte[] expected = Hex.Decode(vector[1]);

                // Load initial message.

                Haraka256Digest haraka = new Haraka256Digest();
                byte[] result = Hex.Decode(vector[0]);
                for (int t = 0; t < 1000; t++)
                {
                    haraka.Update(result, 0, result.Length);
                    haraka.DoFinal(result, 0);
                }
                Assert.IsTrue(Arrays.AreEqual(expected, result));

                //
                // Deliberately introduce incorrect value.
                //

                result[0] ^= 1;
                Assert.IsTrue(!Arrays.AreEqual(expected, result));
                c++;
            }
        }

        private bool Contains(string message, string sub)
        {
            return message.IndexOf(sub) >= 0;
        }

        public override void PerformTest()
        {
            TestKnownVector();
            TestInputTooLong();
            TestInputTooShort();
            TestOutput();
            TestMonty();
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}