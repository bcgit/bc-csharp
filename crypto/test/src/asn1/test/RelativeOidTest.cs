using System;

using NUnit.Framework;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class RelativeOidTest
        : SimpleTest
    {
        private static readonly byte[] req1 = Hex.Decode("0D03813403");
        private static readonly byte[] req2 = Hex.Decode("0D082A36FFFFFFDD6311");

        public override string Name
        {
            get { return "RelativeOID"; }
        }

        private void RecodeCheck(string oid, byte[] enc)
        {
            Asn1RelativeOid o = new Asn1RelativeOid(oid);
            Asn1RelativeOid encO = (Asn1RelativeOid)Asn1Object.FromByteArray(enc);

            if (!o.Equals(encO))
            {
                Fail("relative OID didn't match", o, encO);
            }

            byte[] bytes = o.GetDerEncoded();

            if (!Arrays.AreEqual(bytes, enc))
            {
                Fail("failed comparison test", Hex.ToHexString(enc), Hex.ToHexString(bytes));
            }
        }

        private void CheckValid(string oid)
        {
            Asn1RelativeOid o = new Asn1RelativeOid(oid);
			o = (Asn1RelativeOid)Asn1Object.FromByteArray(o.GetEncoded());

			if (!o.Id.Equals(oid))
			{
                Fail("failed relative oid check for " + oid);
            }
        }

        private void CheckInvalid(string oid)
        {
            try
            {
                new Asn1RelativeOid(oid);
                Fail("failed to catch bad relative oid: " + oid);
            }
            catch (FormatException)
            {
                // expected
            }
        }

        private void BranchCheck(string stem, string branch)
        {
            string expected = stem + "." + branch;
            string actual = new Asn1RelativeOid(stem).Branch(branch).Id;

            if (expected != actual)
            {
                Fail("failed 'branch' check for " + stem + "/" + branch);
            }
        }

        public override void PerformTest()
        {
            RecodeCheck("180.3", req1);
            RecodeCheck("42.54.34359733987.17", req2);

            CheckValid("0");
            CheckValid("37");
            CheckValid("0.1");
            CheckValid("1.0");
            CheckValid("1.0.2");
            CheckValid("1.0.20");
            CheckValid("1.0.200");
            CheckValid("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
            CheckValid("1.2.123.12345678901.1.1.1");
            CheckValid("2.25.196556539987194312349856245628873852187.1");
            CheckValid("3.1");
            CheckValid("37.196556539987194312349856245628873852187.100");
            CheckValid("192.168.1.1");

            CheckInvalid("00");
            CheckInvalid("0.01");
            CheckInvalid("00.1");
            CheckInvalid("1.00.2");
            CheckInvalid("1.0.02");
            CheckInvalid("1.2.00");
            CheckInvalid(".1");
            CheckInvalid("..1");
            CheckInvalid("3..1");
            CheckInvalid(".123452");
            CheckInvalid("1.");
            CheckInvalid("1.345.23.34..234");
            CheckInvalid("1.345.23.34.234.");
            CheckInvalid(".12.345.77.234");
            CheckInvalid(".12.345.77.234.");
            CheckInvalid("1.2.3.4.A.5");
            CheckInvalid("1,2");

            BranchCheck("1.1", "2.2");
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
