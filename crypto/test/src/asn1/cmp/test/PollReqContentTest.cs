using System;

using NUnit.Framework;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Cmp.Tests
{
    [TestFixture]
    public class PollReqContentTest
        : SimpleTest
    {
        public override string Name => "PollReqContentTest";

        public override void PerformTest()
        {
            BigInteger one = BigInteger.ValueOf(1), two = BigInteger.ValueOf(2);
            BigInteger[] ids = new BigInteger[]{ one, two };

            PollReqContent c = new PollReqContent(ids);

            DerInteger[][] vs = c.GetCertReqIDs();

            IsTrue(vs.Length == 2);
            for (int i = 0; i != vs.Length; i++)
            {
                IsTrue(vs[i].Length == 1);
                IsTrue(vs[i][0].Value.Equals(ids[i]));
            }

            BigInteger[] values = c.GetCertReqIDValues();

            IsTrue(values.Length == 2);
            for (int i = 0; i != values.Length; i++)
            {
                IsTrue(values[i].Equals(ids[i]));
            }

            c = new PollReqContent(two);
            vs = c.GetCertReqIDs();

            IsTrue(vs.Length == 1);

            IsTrue(vs[0].Length == 1);
            IsTrue(vs[0][0].Value.Equals(two));
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
