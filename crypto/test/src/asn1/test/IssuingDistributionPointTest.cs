using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Asn1.Tests
{
    [TestFixture]
    public class IssuingDistributionPointUnitTest
        : SimpleTest
    {
        public override string Name => "IssuingDistributionPoint";

        public override void PerformTest()
        {
            DistributionPointName name = new DistributionPointName(
                new GeneralNames(new GeneralName(new X509Name("cn=test"))));
            ReasonFlags reasonFlags = new ReasonFlags(ReasonFlags.CACompromise);

            CheckOnlyException(name, true, true, reasonFlags, true, true);
            CheckOnlyException(name, true, true, reasonFlags, true, false);
            CheckOnlyException(name, true, false, reasonFlags, true, true);

            CheckPoint(2, name, false, false, reasonFlags, false, false);
            CheckPoint(0, null, false, false, null, false, false);

            try
            {
                IssuingDistributionPoint.GetInstance(new object());

                Fail("GetInstance() failed to detect bad object.");
            }
            catch (ArgumentException)
            {
                // expected
            }
        }

        private void CheckOnlyException(DistributionPointName distributionPoint, bool onlyContainsUserCerts,
            bool onlyContainsCACerts, ReasonFlags onlySomeReasons, bool indirectCRL, bool onlyContainsAttributeCerts)
        {
            try
            {
                new IssuingDistributionPoint(distributionPoint, onlyContainsUserCerts, onlyContainsCACerts,
                    onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);
                Fail("no exception");
            }
            catch (ArgumentException e)
            {
                IsEquals("only one of onlyContainsCACerts, onlyContainsUserCerts, or onlyContainsAttributeCerts can be true", e.Message);
            }
        }

        private void CheckPoint(int size, DistributionPointName distributionPoint, bool onlyContainsUserCerts,
            bool onlyContainsCACerts, ReasonFlags onlySomeReasons, bool indirectCRL, bool onlyContainsAttributeCerts)
        {
            IssuingDistributionPoint point = new IssuingDistributionPoint(distributionPoint, onlyContainsUserCerts,
                onlyContainsCACerts, onlySomeReasons, indirectCRL, onlyContainsAttributeCerts);

            CheckValues(point, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons,
                indirectCRL, onlyContainsAttributeCerts);

            Asn1Sequence seq = Asn1Sequence.GetInstance(point.GetEncoded());
            IsEquals("size mismatch", seq.Count, size);

            point = IssuingDistributionPoint.GetInstance(seq);

            CheckValues(point, distributionPoint, onlyContainsUserCerts, onlyContainsCACerts, onlySomeReasons,
                indirectCRL, onlyContainsAttributeCerts);
        }

        private void CheckValues(IssuingDistributionPoint point, DistributionPointName distributionPoint,
            bool onlyContainsUserCerts, bool onlyContainsCACerts, ReasonFlags onlySomeReasons, bool indirectCRL,
            bool onlyContainsAttributeCerts)
        {
            IsEquals("mismatch on onlyContainsUserCerts", point.OnlyContainsUserCerts, onlyContainsUserCerts);
            IsEquals("mismatch on onlyContainsCACerts", point.OnlyContainsCACerts, onlyContainsCACerts);
            IsEquals("mismatch on indirectCRL", point.IsIndirectCrl, indirectCRL);
            IsEquals("mismatch on onlyContainsAttributeCerts", point.OnlyContainsAttributeCerts, onlyContainsAttributeCerts);
            IsTrue("mismatch on onlySomeReasons", Object.Equals(onlySomeReasons, point.OnlySomeReasons));
            IsTrue("mismatch on distributionPoint", Object.Equals(distributionPoint, point.DistributionPoint));
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}
