using System;
using System.Collections;
using System.Text;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Math.EC.Tests
{
    /**
    * Compares the performance of the the window NAF point multiplication against
    * conventional point multiplication.
    */
    [TestFixture, Explicit]
    public class ECPointPerformanceTest
    {
        internal const int MULTS_PER_ROUND = 100;
        internal const int PRE_ROUNDS = 2;
        internal const int NUM_ROUNDS = 10;

        private static string[] COORD_NAMES = new string[]{ "AFFINE", "HOMOGENEOUS", "JACOBIAN", "JACOBIAN-CHUDNOVSKY",
            "JACOBIAN-MODIFIED", "LAMBDA-AFFINE", "LAMBDA-PROJECTIVE", "SKEWED" };

        private void RandMult(string curveName)
        {
            X9ECParameters spec = ECNamedCurveTable.GetByName(curveName);
            if (spec != null)
            {
                RandMult(curveName, spec);
            }

            spec = CustomNamedCurves.GetByName(curveName);
            if (spec != null)
            {
                RandMult(curveName + " (custom)", spec);
            }
        }

        private void RandMult(string label, X9ECParameters spec)
        {
            ECCurve C = spec.Curve;
            ECPoint G = (ECPoint)spec.G;
            BigInteger n = spec.N;

            SecureRandom random = new SecureRandom();
            random.SetSeed(DateTimeUtilities.CurrentUnixMs());

            Console.WriteLine(label);

            int[] coords = ECCurve.GetAllCoordinateSystems();
            for (int i = 0; i < coords.Length; ++i)
            {
                int coord = coords[i];
                if (C.SupportsCoordinateSystem(coord))
                {
                    ECCurve c = C;
                    ECPoint g = G;

                    if (c.CoordinateSystem != coord)
                    {
                        c = C.Configure().SetCoordinateSystem(coord).Create();
                        g = c.ImportPoint(G);
                    }

                    double avgDuration = RandMult(random, g, n);
                    string coordName = COORD_NAMES[coord];
                    StringBuilder sb = new StringBuilder();
                    sb.Append("  ");
                    sb.Append(coordName);
                    for (int j = coordName.Length; j < 30; ++j)
                    {
                        sb.Append(' ');
                    }
                    sb.Append(": ");
                    sb.Append(avgDuration);
                    sb.Append("ms");
                    Console.WriteLine(sb.ToString());
                }
            }
        }

        private double RandMult(SecureRandom random, ECPoint g, BigInteger n)
        {
            BigInteger[] ks = new BigInteger[128];
            for (int i = 0; i < ks.Length; ++i)
            {
                ks[i] = new BigInteger(n.BitLength - 1, random);
            }

            int ki = 0;
            ECPoint p = g;
            for (int i = 1; i <= PRE_ROUNDS; i++)
            {
                for (int j = 0; j < MULTS_PER_ROUND; ++j)
                {
                    BigInteger k = ks[ki];
                    p = g.Multiply(k);
                    if ((ki & 1) != 0)
                    {
                        g = p;
                    }
                    if (++ki == ks.Length)
                    {
                        ki = 0;
                    }
                }
            }

            double minElapsed = Double.MaxValue, maxElapsed = Double.MinValue, totalElapsed = 0.0;

            for (int i = 1; i <= NUM_ROUNDS; i++)
            {
                long startTime = DateTimeUtilities.CurrentUnixMs();

                for (int j = 0; j < MULTS_PER_ROUND; ++j)
                {
                    BigInteger k = ks[ki];
                    p = g.Multiply(k);
                    if ((ki & 1) != 0)
                    {
                        g = p;
                    }
                    if (++ki == ks.Length)
                    {
                        ki = 0;
                    }
                }

                long endTime = DateTimeUtilities.CurrentUnixMs();

                double roundElapsed = (double)(endTime - startTime);
                minElapsed = System.Math.Min(minElapsed, roundElapsed);
                maxElapsed = System.Math.Max(maxElapsed, roundElapsed);
                totalElapsed += roundElapsed;
            }

            return (totalElapsed - minElapsed - maxElapsed) / (NUM_ROUNDS - 2) / MULTS_PER_ROUND;
        }

        [Test]
        public void TestMultiply()
        {
            ArrayList nameList = new ArrayList();
            CollectionUtilities.AddRange(nameList, ECNamedCurveTable.Names);
            string[] names = (string[])nameList.ToArray(typeof(string));
            Array.Sort(names);
            ISet oids = new HashSet();
            foreach (string name in names)
            {
                DerObjectIdentifier oid = ECNamedCurveTable.GetOid(name);
                if (!oids.Contains(oid))
                {
                    oids.Add(oid);
                    RandMult(name);
                }
            }
        }

        public static void Main(string[] args)
        {
            new ECPointPerformanceTest().TestMultiply();
        }
    }
}
