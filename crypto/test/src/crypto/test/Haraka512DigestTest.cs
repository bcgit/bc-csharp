using System;
using NUnit.Framework;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class Haraka512DigestTest : SimpleTest
    {
        public override string Name
        {
            get { return "Haraka 512"; }
        }

        public void TestKnownVector()
        {
            byte[] input = new byte[64];
            for (int t = 0; t < input.Length; t++)
            {
                input[t] = (byte)t;
            }

            // From Appendix B, Haraka-512 v2, https://eprint.iacr.org/2016/098.pdf
            byte[] expected512 = Hex.Decode("be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa");

            Haraka512Digest haraka = new Haraka512Digest();
            haraka.Update(input, 0, input.Length);
            byte[] output = new byte[haraka.GetDigestSize()];
            haraka.DoFinal(output, 0);
            Assert.IsTrue(Arrays.AreEqual(expected512, output));
        }

        public void TestInputTooShort()
        {
            try
            {
                Haraka512Digest haraka = new Haraka512Digest();
                byte[] input = new byte[63];
                haraka.Update(input, 0, input.Length);
                haraka.DoFinal(null, 0);
                Assert.Fail("fail on input not 64 bytes.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "input must be exactly 64 bytes"));
            }
        }

        public void TestInputTooLong()
        {
            try
            {
                Haraka512Digest haraka = new Haraka512Digest();
                byte[] input = new byte[65];
                haraka.Update(input, 0, input.Length);
                haraka.DoFinal(null, 0);
                Assert.Fail("fail on input not 64 bytes.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "total input cannot be more than 64 bytes"));
            }
        }

        public void TestOutput()
        {
            //
            // Buffer too short.
            //
            try
            {
                Haraka512Digest haraka = new Haraka512Digest();
                byte[] input = new byte[64];
                haraka.Update(input, 0, input.Length);
                byte[] output = new byte[31];
                haraka.DoFinal(output, 0);
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
                Haraka512Digest haraka = new Haraka512Digest();
                byte[] input = new byte[64];
                haraka.Update(input, 0, input.Length);
                byte[] output = new byte[48];
                haraka.DoFinal(output, 17);
                Assert.Fail("Output too short for digest result.");
            }
            catch (ArgumentException e)
            {
                Assert.IsTrue(Contains(e.Message, "output too short to receive digest"));
            }

            //
            // Offset output..
            //
            {
                byte[] input = new byte[64];
                for (int t = 0; t < input.Length; t++)
                {
                    input[t] = (byte)t;
                }

                byte[] expected512 = Hex.Decode("00000000be7f723b4e80a99813b292287f306f625a6d57331cae5f34dd9277b0945be2aa");

                Haraka512Digest haraka = new Haraka512Digest();
                haraka.Update(input, 0, input.Length);
                byte[] output = new byte[haraka.GetDigestSize() + 4];
                haraka.DoFinal(output, 4);
                Assert.IsTrue(Arrays.AreEqual(expected512, output));
            }

        }

        void TestMonty()
        {
            int c = 0;
            string[][] vectors = new string[][]{
            new string[]{
                "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
                "ABE210FE673F3B28E70E5100C476D82F61A7E2BDB3D8423FB0A15E5DE3D3A4DE"
            },
            new string[]{
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                "5F5ECB52C61F5036C96BE555D2E18C520AB3ED093954700C283A322D14DBFE02"
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
                byte[] input = Hex.Decode(vector[0]);
                Haraka512Digest haraka = new Haraka512Digest();
                byte[] result = new byte[haraka.GetDigestSize()];
                for (int t = 0; t < 1000; t++)
                {
                    haraka.Update(input, 0, input.Length);
                    haraka.DoFinal(result, 0);

                    if ((t & 0x01) == 1)
                    {
                        Array.Copy(result, 0, input, 0, result.Length);
                    }
                    else
                    {
                        Array.Copy(result, 0, input, result.Length, result.Length);
                    }
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