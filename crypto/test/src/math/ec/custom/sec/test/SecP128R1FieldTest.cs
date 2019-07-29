using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Custom.Sec.Tests
{
    [TestFixture]
    public class SecP128R1FieldTest
    {
        [Test]
        public void Test_GitHub566()
        {
            uint[] x = new uint[]{ 0x4B1E2F5E, 0x09E29D21, 0xA58407ED, 0x6FC3C7CF };
            uint[] y = new uint[]{ 0x2FFE8892, 0x55CA61CA, 0x0AF780B5, 0x4BD7B797 };
            uint[] z = Nat128.Create();

            SecP128R1Field.Multiply(x, y, z);

            uint[] expected = new uint[]{ 0x01FFFF01, 0, 0, 0 };
            Assert.IsTrue(Arrays.AreEqual(expected, z));
        }

        [Test]
        public void TestReduce32()
        {
            uint[] z = Nat128.Create();
            //Arrays.Fill(z, 0xFFFFFFFF);
            for (int i = 0; i < z.Length; ++i)
            {
                z[i] = 0xFFFFFFFF;
            }

            SecP128R1Field.Reduce32(0xFFFFFFFF, z);

            uint[] expected = new uint[]{ 1, 1, 0, 4 };
            Assert.IsTrue(Arrays.AreEqual(expected, z));
        }
    }
}
