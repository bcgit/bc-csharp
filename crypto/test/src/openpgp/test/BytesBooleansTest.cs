using System;

using NUnit.Framework;

using Org.BouncyCastle.Bcpg.Sig;

namespace Org.BouncyCastle.Bcpg.OpenPgp.Tests
{
    [TestFixture]
    public class BytesBooleansTest
    {
        [Test]
        public void TestParseFalse()
        {
            PrimaryUserId primaryUserID = new PrimaryUserId(true, false);
            byte[] bFalse = primaryUserID.GetData();

            Assert.AreEqual(1, bFalse.Length);
            Assert.AreEqual(0, bFalse[0]);
            Assert.False(primaryUserID.IsPrimaryUserId());
        }

        [Test]
        public void TestParseTrue()
        {
            PrimaryUserId primaryUserID = new PrimaryUserId(true, true);
            byte[] bTrue = primaryUserID.GetData();

            Assert.AreEqual(1, bTrue.Length);
            Assert.AreEqual(1, bTrue[0]);
            Assert.True(primaryUserID.IsPrimaryUserId());
        }

        [Test]
        public void TestParseTooShort()
        {
            PrimaryUserId primaryUserID = new PrimaryUserId(true, false, new byte[0]);
            byte[] bTooShort = primaryUserID.GetData();

            try
            {
                primaryUserID.IsPrimaryUserId();
                Assert.Fail("Should throw.");
            }
            catch (InvalidOperationException)
            {
                // expected.
            }
        }

        [Test]
        public void TestParseTooLong()
        {
            PrimaryUserId primaryUserID = new PrimaryUserId(true, false, new byte[42]);
            byte[] bTooLong = primaryUserID.GetData();

            try
            {
                primaryUserID.IsPrimaryUserId();
                Assert.Fail("Should throw.");
            }
            catch (InvalidOperationException)
            {
                // expected.
            }
        }
    }
}
