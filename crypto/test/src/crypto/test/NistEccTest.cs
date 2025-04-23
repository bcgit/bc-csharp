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
    public class NistEccTest
    {
        [Test]
        public void TestVectors()
        {
            foreach (object[] testVector in CollectTestVectors())
            {
                var curve = testVector[0] as string;
                var k = testVector[1] as BigInteger;
                var expectedX = testVector[2] as BigInteger;
                var expectedY = testVector[3] as BigInteger;

                ImplTestMultiply(curve, k, expectedX, expectedY);
            }
        }

        private static IEnumerable<object[]> CollectTestVectors()
        {
            var testVectors = new List<object[]>();
            string curve = null;
            BigInteger k = null;
            BigInteger x = null;
            BigInteger y = null;

            Regex capture = new Regex(@"^ ?(\w+):? =? ?(\w+)", RegexOptions.Compiled);

            using (StreamReader r = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.nist_ecc.txt")))
            {
                string line;
                while (null != (line = r.ReadLine()))
                {
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
                        testVectors.Add(new object[]{ curve, k, x, y });
                        k = null;
                        x = null;
                        y = null;
                    }
                }
            }

            return testVectors;
        }

        private static void ImplTestMultiply(string curve, BigInteger k, BigInteger expectedX, BigInteger expectedY)
        {
            // Arrange
            X9ECParameters x9EcParameters = Asn1.Nist.NistNamedCurves.GetByName(curve);

            // Act
            ECPoint ecPoint = x9EcParameters.G.Multiply(k).Normalize();

            // Assert
            Assert.AreEqual(expectedX, ecPoint.AffineXCoord.ToBigInteger(), "Unexpected X Coordinate");
            Assert.AreEqual(expectedY, ecPoint.AffineYCoord.ToBigInteger(), "Unexpected Y Coordinate");
        }
    }
}
