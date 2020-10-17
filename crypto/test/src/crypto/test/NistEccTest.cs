using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using NUnit.Framework;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class NistEccTest
    {
        public IEnumerable<object[]> CollectTestVectors()
        {
            string curve = null;
            BigInteger k = null;
            BigInteger x = null;
            BigInteger y = null;

            using (StreamReader r = new StreamReader(SimpleTest.GetTestDataAsStream("crypto.nist_ecc.txt")))
            {
                string line;
                while (null != (line = r.ReadLine()))
                {
                    var capture = new Regex(@"^ ?(\w+):? =? ?(\w+)", RegexOptions.Compiled);
                    var data = capture.Match(line);

                    if (!data.Success) continue;
                    var nistKey = data.Groups[1].Value;
                    var nistValue = data.Groups[2].Value;
                    switch (nistKey)
                    {
                        case "Curve":
                            // Change curve name from LNNN to L-NNN ie: P256 to P-256
                            curve = $"{nistValue.Substring(0, 1)}-{nistValue.Substring(1)}";
                            break;
                        case "k":
                            k = new BigInteger(nistValue, 10);
                            break;
                        case "x":
                            x = new BigInteger(nistValue, radix: 16);
                            break;
                        case "y":
                            y = new BigInteger(nistValue, radix: 16);
                            break;
                    }

                    if (null != curve && null != k && null != x && null != y)
                    {
                        yield return new object[] {curve, k, x, y};
                        k = null;
                        x = null;
                        y = null;
                    }
                }
            }
        }

        [TestCaseSource(nameof(CollectTestVectors))]
        public void TestMultiply(string curve, BigInteger k, BigInteger expectedX, BigInteger expectedY)
        {
            // Arrange
            var x9EcParameters = Asn1.Nist.NistNamedCurves.GetByName(curve);

            // Act
            var ecPoint = x9EcParameters.G.Multiply(k).Normalize();

            // Assert
            Assert.AreEqual(expectedX, ecPoint.XCoord.ToBigInteger(), "Unexpected X Coordinate");
            Assert.AreEqual(expectedY, ecPoint.YCoord.ToBigInteger(), "Unexpected Y Coordinate");
        }
    }
}