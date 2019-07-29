using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;

namespace Org.BouncyCastle.Math.EC.Custom.Sec.Tests
{
    [TestFixture]
    public class SecP128R1FieldTest
    {
        private static readonly X9ECParameters DP = CustomNamedCurves
            .GetByOid(SecObjectIdentifiers.SecP128r1);

        [Test]
        public void Test_GitHub566()
        {
            uint[] x = new uint[]{ 0x4B1E2F5E, 0x09E29D21, 0xA58407ED, 0x6FC3C7CF };
            uint[] y = new uint[]{ 0x2FFE8892, 0x55CA61CA, 0x0AF780B5, 0x4BD7B797 };

            ECFieldElement Z = FE(x).Multiply(FE(y));

            uint[] expected = new uint[] { 0x01FFFF01, 0, 0, 0 };
            Assert.AreEqual(FE(expected), Z);
        }

        private ECFieldElement FE(BigInteger x)
        {
            return DP.Curve.FromBigInteger(x);
        }

        private ECFieldElement FE(uint[] x)
        {
            return FE(Nat128_ToBigInteger(x));
        }

        private static BigInteger Nat128_ToBigInteger(uint[] x)
        {
            byte[] bs = new byte[16];
            for (int i = 0; i < 4; ++i)
            {
                uint x_i = x[i];
                if (x_i != 0)
                {
                    Pack_UInt32_To_BE(x_i, bs, (3 - i) << 2);
                }
            }
            return new BigInteger(1, bs);
        }

        private static void Pack_UInt32_To_BE(uint n, byte[] bs, int off)
        {
            bs[off] = (byte)(n >> 24);
            bs[off + 1] = (byte)(n >> 16);
            bs[off + 2] = (byte)(n >> 8);
            bs[off + 3] = (byte)(n);
        }
    }
}
