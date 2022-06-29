using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    [TestFixture]
    public class NistEccTest : SimpleTest
    {
        public override string Name
        {
            get { return "NistEcc"; }
        }

        public override void PerformTest()
        {
            foreach (object[] testVector in CollectTestVectors())
            {
                TestMultiply(
                    testVector[0] as string,
                    testVector[1] as BigInteger,
                    testVector[2] as BigInteger,
                    testVector[3] as BigInteger
                    );
            }
        }

        public IEnumerable<object[]> CollectTestVectors()
        {
            var testVectors = new List<object[]>();
            string curve = null;
            BigInteger k = null;
            BigInteger x = null;
            BigInteger y = null;

            using (StreamReader r = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.nist_ecc.txt")))
            {
                string line;
                while (null != (line = r.ReadLine()))
                {
                    Regex capture = new Regex(@"^ ?(\w+):? =? ?(\w+)", RegexOptions.Compiled);
                    Match data = capture.Match(line);
                    if (!data.Success)
                        continue;

                    string nistKey = data.Groups[1].Value;
                    string nistValue = data.Groups[2].Value;
                    switch (nistKey)
                    {
                        case "Curve":
                            // Change curve name from LNNN to L-NNN ie: P256 to P-256
                            curve = nistValue.Insert(1, "-");
                            break;
                        case "k":
                            k = new BigInteger(nistValue, 10);
                            break;
                        case "x":
                            x = new BigInteger(nistValue, 16);
                            break;
                        case "y":
                            y = new BigInteger(nistValue, 16);
                            break;
                    }

                    if (null != curve && null != k && null != x && null != y)
                    {
                        testVectors.Add(new object[]{curve, k, x, y});
                        k = null;
                        x = null;
                        y = null;
                    }
                }
            }

            return testVectors;
        }

        public void TestMultiply(string curve, BigInteger k, BigInteger expectedX, BigInteger expectedY)
        {
            // Arrange
            X9ECParameters x9EcParameters = Asn1.Nist.NistNamedCurves.GetByName(curve);

            // Act
            ECPoint ecPoint = x9EcParameters.G.Multiply(k).Normalize();

            // Assert
            IsEquals("Unexpected X Coordinate", expectedX, ecPoint.AffineXCoord.ToBigInteger());
            IsEquals("Unexpected Y Coordinate", expectedY, ecPoint.AffineYCoord.ToBigInteger());
        }

        [Test]
        public void TestFunction()
        {
            string resultText = Perform().ToString();

            Assert.AreEqual(Name + ": Okay", resultText);
        }
    }
}