using System;

using NUnit.Framework;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// Test cases for the XmssUtilities class.
    /// </summary>
    [TestFixture]
    public class XmssUtilTests
    {
        [Test]
        public void TestLog2()
        {
            Assert.AreEqual(3, XmssUtilities.Log2(8));
            Assert.AreEqual(3, XmssUtilities.Log2(10));
            Assert.AreEqual(26, XmssUtilities.Log2(100010124));
        }

        [Test]
        public void TestIntToBytesBigEndian()
        {
            byte[] b = XmssUtilities.ToBytesBigEndian(1, 4);
            Assert.AreEqual(4, b.Length);
            Assert.AreEqual((byte)0x00, b[0]);
            Assert.AreEqual((byte)0x00, b[1]);
            Assert.AreEqual((byte)0x00, b[2]);
            Assert.AreEqual((byte)0x01, b[3]);
            b = XmssUtilities.ToBytesBigEndian(1, 6);
            Assert.AreEqual(6, b.Length);
            Assert.AreEqual((byte)0x00, b[0]);
            Assert.AreEqual((byte)0x00, b[1]);
            Assert.AreEqual((byte)0x00, b[2]);
            Assert.AreEqual((byte)0x00, b[3]);
            Assert.AreEqual((byte)0x00, b[4]);
            Assert.AreEqual((byte)0x01, b[5]);
            b = XmssUtilities.ToBytesBigEndian(1, 32);
            Assert.AreEqual(32, b.Length);
            for (int i = 0; i < 31; i++)
            {
                Assert.AreEqual((byte)0x00, b[i]);
            }
            b = XmssUtilities.ToBytesBigEndian(12345, 5);
            Assert.AreEqual(5, b.Length);
            Assert.AreEqual((byte)0x00, b[0]);
            Assert.AreEqual((byte)0x00, b[1]);
            Assert.AreEqual((byte)0x00, b[2]);
            Assert.AreEqual((byte)0x30, b[3]);
            Assert.AreEqual((byte)0x39, b[4]);
        }

        [Test]
        public void TestLongToBytesBigEndian()
        {
            byte[] b = XmssUtilities.ToBytesBigEndian(1, 8);
            Assert.AreEqual(8, b.Length);
            Assert.AreEqual((byte)0x00, b[0]);
            Assert.AreEqual((byte)0x00, b[1]);
            Assert.AreEqual((byte)0x00, b[2]);
            Assert.AreEqual((byte)0x00, b[3]);
            Assert.AreEqual((byte)0x00, b[4]);
            Assert.AreEqual((byte)0x00, b[5]);
            Assert.AreEqual((byte)0x00, b[6]);
            Assert.AreEqual((byte)0x01, b[7]);
            b = XmssUtilities.ToBytesBigEndian(1, 10);
            Assert.AreEqual(10, b.Length);
            Assert.AreEqual((byte)0x00, b[0]);
            Assert.AreEqual((byte)0x00, b[1]);
            Assert.AreEqual((byte)0x00, b[2]);
            Assert.AreEqual((byte)0x00, b[3]);
            Assert.AreEqual((byte)0x00, b[4]);
            Assert.AreEqual((byte)0x00, b[5]);
            Assert.AreEqual((byte)0x00, b[6]);
            Assert.AreEqual((byte)0x00, b[7]);
            Assert.AreEqual((byte)0x00, b[8]);
            Assert.AreEqual((byte)0x01, b[9]);
            b = XmssUtilities.ToBytesBigEndian(1, 32);
            for (int i = 0; i < 31; i++)
            {
                Assert.AreEqual((byte)0x00, b[i]);
            }
            Assert.AreEqual((byte)0x01, b[31]);
            b = XmssUtilities.ToBytesBigEndian(12345, 9);
            Assert.AreEqual(9, b.Length);
            Assert.AreEqual((byte)0x00, b[0]);
            Assert.AreEqual((byte)0x00, b[1]);
            Assert.AreEqual((byte)0x00, b[2]);
            Assert.AreEqual((byte)0x00, b[3]);
            Assert.AreEqual((byte)0x00, b[4]);
            Assert.AreEqual((byte)0x00, b[5]);
            Assert.AreEqual((byte)0x00, b[6]);
            Assert.AreEqual((byte)0x30, b[7]);
            Assert.AreEqual((byte)0x39, b[8]);
        }

        [Test]
        public void TestLongToBytesBigEndianOffsetException()
        {
            byte[] input = new byte[8];
            Assert.Catch<Exception>(() => Pack.UInt64_To_BE(1UL, input, 1));
        }

        [Test]
        public void TestLongToBytesBigEndianOffset()
        {
            byte[] input = new byte[32];
            Pack.UInt64_To_BE(12345UL, input, 5);
            Assert.AreEqual((byte)0x00, input[0]);
            Assert.AreEqual((byte)0x00, input[1]);
            Assert.AreEqual((byte)0x00, input[2]);
            Assert.AreEqual((byte)0x00, input[3]);
            Assert.AreEqual((byte)0x00, input[4]);
            Assert.AreEqual((byte)0x00, input[5]);
            Assert.AreEqual((byte)0x00, input[6]);
            Assert.AreEqual((byte)0x00, input[7]);
            Assert.AreEqual((byte)0x00, input[8]);
            Assert.AreEqual((byte)0x00, input[9]);
            Assert.AreEqual((byte)0x00, input[10]);
            Assert.AreEqual((byte)0x30, input[11]);
            Assert.AreEqual((byte)0x39, input[12]);
            for (int i = 14; i < input.Length; i++)
            {
                Assert.AreEqual((byte)0x00, input[i]);
            }
            input = new byte[32];
            Pack.UInt64_To_BE(12345UL, input, 24);
            for (int i = 0; i < 24; i++)
            {
                Assert.AreEqual((byte)0x00, input[i]);
            }
            Assert.AreEqual((byte)0x00, input[28]);
            Assert.AreEqual((byte)0x00, input[29]);
            Assert.AreEqual((byte)0x30, input[30]);
            Assert.AreEqual((byte)0x39, input[31]);
        }

        [Test]
        public void TestBytesToIntBigEndianException()
        {
            byte[] input = new byte[4];
            Assert.Catch<Exception>(() => Pack.BE_To_UInt32(input, 1));
        }

        [Test]
        public void TestBytesToIntBigEndian()
        {
            byte[] in1 = { 0x00, 0xff, 0x00, 0xff };
            int output = (int)Pack.BE_To_UInt32(in1, 0);
            Assert.AreEqual(16711935, output);
            byte[] in2 = { 0xab, 0xcd, 0xef, 0xaa };
            output = (int)Pack.BE_To_UInt32(in2, 0);
            Assert.AreEqual("2882400170", new BigInteger(1, in2).ToString());
            byte[] in3 = new byte[100];
            Arrays.Fill(in3, 0xaa);
            for (int i = 35; i < 39; i++)
            {
                in3[i] = 0xff;
            }
            output = (int)Pack.BE_To_UInt32(in3, 35);
            Assert.AreEqual(new BigInteger("4294967295"), BigInteger.ValueOf(output & 0xffffffffL));
        }

        [Test]
        public void TestBytesToLongBigEndianException()
        {
            byte[] input = new byte[10];
            Assert.Catch<Exception>(() => Pack.BE_To_UInt64(input, 3));
        }

        [Test]
        public void TestBytesToLongBigEndian()
        {
            byte[] in1 = { 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff };
            long output = (long)Pack.BE_To_UInt64(in1, 0);
            Assert.AreEqual(71777214294589695L, output);
            byte[] in2 = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
            output = (long)Pack.BE_To_UInt64(in2, 0);
            Assert.AreEqual("18446744073709551615", new BigInteger(1, in2).ToString());
        }

        [Test]
        public void TestCalculateTau()
        {
            int height = 10;
            for (int index = 0; index < (1 << 10); index += 2)
            {
                Assert.AreEqual(0, XmssUtilities.CalculateTau(index, height));
            }
            Assert.AreEqual(9, XmssUtilities.CalculateTau(511, height));
        }
    }
}
