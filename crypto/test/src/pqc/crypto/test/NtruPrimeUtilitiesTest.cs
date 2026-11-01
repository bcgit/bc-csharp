using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Pqc.Crypto.NtruPrime;

namespace Org.BouncyCastle.Pqc.Crypto.Tests
{
    /// <summary>
    /// Tests for the arithmetic in NTRU Prime's <see cref="NtruPrimeUtilities"/>.
    /// </summary>
    /// <remarks>
    /// The KATs only reach the inputs their seeds produce, so these tests compare the arithmetic with a plain
    /// reference - a schoolbook product in long arithmetic and the % operator - for every parameter set, including the
    /// largest operands the callers can pass.
    /// </remarks>
    [TestFixture]
    public class NtruPrimeUtilitiesTest
    {
        // { p, q } of every parameter set
        private static readonly int[][] PQ = GetPQ();

        private readonly Random m_random = new Random(1);

        [Test]
        public void TestFreeze()
        {
            var moduli = new List<int>{ 3 };
            foreach (int[] pq in PQ)
            {
                moduli.Add(pq[1]);
            }

            foreach (int n in moduli)
            {
                int barrett = NtruPrimeUtilities.GetBarrettFactor(n);
                int max = int.MaxValue - (n - 1) / 2;

                for (int x = -(1 << 18); x <= (1 << 18); x++)
                {
                    CheckFreeze(x, n, barrett);
                }
                for (int i = 0; i < 1000; i++)
                {
                    CheckFreeze(int.MinValue + i, n, barrett);
                    CheckFreeze(max - i, n, barrett);
                }
                for (int i = 0; i < 200000; i++)
                {
                    int x = (int)NextUInt32();
                    if (x <= max)
                    {
                        CheckFreeze(x, n, barrett);
                    }
                }
            }

            Assert.AreEqual(NtruPrimeUtilities.GetBarrettFactor(3), NtruPrimeUtilities.Barrett3);
            for (int x = -1000; x <= 1000; x++)
            {
                Assert.AreEqual(CentredMod(x, 3), NtruPrimeUtilities.Freeze3(x));
            }
        }

        [Test]
        public void TestRqMult()
        {
            foreach (int[] pq in PQ)
            {
                int p = pq[0], q = pq[1], half = (q - 1) / 2;

                // the extremes: every coefficient of the reduced factor at +-(q - 1) / 2, the small factor at +-2 (a
                // decoded small polynomial can hold 2), and alternating signs
                int[][] extremes = { new int[]{ half, 2 }, new int[]{ -half, 2 }, new int[]{ half, -2 },
                    new int[]{ -half, -2 }, new int[]{ half, 1 }, new int[]{ -half, -1 } };
                foreach (int[] e in extremes)
                {
                    short[] f = new short[p];
                    sbyte[] g = new sbyte[p];
                    for (int i = 0; i < p; i++)
                    {
                        f[i] = (short)e[0];
                        g[i] = (sbyte)e[1];
                    }
                    CheckRqMult(f, g, p, q);

                    for (int i = 0; i < p; i += 2)
                    {
                        f[i] = (short)-f[i];
                    }
                    CheckRqMult(f, g, p, q);
                }

                for (int trial = 0; trial < 10; trial++)
                {
                    short[] f = new short[p];
                    sbyte[] g = new sbyte[p];
                    for (int i = 0; i < p; i++)
                    {
                        f[i] = (short)(m_random.Next(q) - half);
                        g[i] = (sbyte)(trial < 5 ? m_random.Next(3) - 1 : m_random.Next(5) - 2);
                    }
                    CheckRqMult(f, g, p, q);
                }
            }
        }

        [Test]
        public void TestR3Mult()
        {
            foreach (int[] pq in PQ)
            {
                int p = pq[0];

                int[][] extremes = { new int[]{ 1, 2 }, new int[]{ -1, 2 }, new int[]{ 1, -1 }, new int[]{ -1, -1 } };
                foreach (int[] e in extremes)
                {
                    sbyte[] f = new sbyte[p];
                    sbyte[] g = new sbyte[p];
                    for (int i = 0; i < p; i++)
                    {
                        f[i] = (sbyte)e[0];
                        g[i] = (sbyte)e[1];
                    }
                    CheckR3Mult(f, g, p);
                }

                for (int trial = 0; trial < 10; trial++)
                {
                    sbyte[] f = new sbyte[p];
                    sbyte[] g = new sbyte[p];
                    for (int i = 0; i < p; i++)
                    {
                        f[i] = (sbyte)(m_random.Next(3) - 1);
                        g[i] = (sbyte)(m_random.Next(4) - 1);
                    }
                    CheckR3Mult(f, g, p);
                }
            }
        }

        [Test]
        public void TestFqRecip()
        {
            foreach (int[] pq in PQ)
            {
                int q = pq[1], half = (q - 1) / 2;
                for (int x = -half; x <= half; x++)
                {
                    int inv = NtruPrimeUtilities.FqRecip(x, q);
                    if (inv < -half || inv > half || CentredMod((long)x * inv, q) != (x == 0 ? 0 : 1))
                    {
                        Assert.Fail("FqRecip(" + x + ", " + q + ") = " + inv);
                    }
                }
            }
        }

        [Test]
        public void TestRqRecip3()
        {
            foreach (int[] pq in PQ)
            {
                int p = pq[0], q = pq[1];

                // a short polynomial: weight about p / 3, coefficients in {-1, 1}
                sbyte[] f = new sbyte[p];
                for (int i = 0; i < p; i++)
                {
                    f[i] = (sbyte)(m_random.Next(3) == 0 ? m_random.Next(2) * 2 - 1 : 0);
                }

                short[] finv3 = new short[p];
                Assert.AreEqual(0, NtruPrimeUtilities.RqRecip3(finv3, f, p, q));

                // finv3 * 3f = 1
                long[] product = ReferenceProduct(ToInts(finv3), ToInts(f), p);
                for (int i = 0; i < p; i++)
                {
                    Assert.AreEqual(i == 0 ? 1 : 0, CentredMod(3 * product[i], q), "p = " + p + ", coefficient " + i);
                }
            }
        }

        [Test]
        public void TestR3Recip()
        {
            foreach (int[] pq in PQ)
            {
                int p = pq[0];

                // 0 has no inverse, and the constants 1 and -1 are their own
                sbyte[] constant = new sbyte[p];
                sbyte[] constantInv = new sbyte[p];
                Assert.AreEqual(-1, NtruPrimeUtilities.R3Recip(constantInv, constant, p));

                for (int c = -1; c <= 1; c += 2)
                {
                    constant[0] = (sbyte)c;
                    Assert.AreEqual(0, NtruPrimeUtilities.R3Recip(constantInv, constant, p));
                    Assert.AreEqual(c, constantInv[0]);
                    for (int i = 1; i < p; i++)
                    {
                        Assert.AreEqual(0, constantInv[i]);
                    }
                }

                int found = 0;
                for (int trial = 0; trial < 4; trial++)
                {
                    sbyte[] g = new sbyte[p];
                    for (int i = 0; i < p; i++)
                    {
                        g[i] = (sbyte)(m_random.Next(3) - 1);
                    }

                    sbyte[] ginv = new sbyte[p];
                    if (NtruPrimeUtilities.R3Recip(ginv, g, p) != 0)
                    {
                        continue;
                    }

                    found++;

                    long[] product = ReferenceProduct(ToInts(g), ToInts(ginv), p);
                    for (int i = 0; i < p; i++)
                    {
                        Assert.AreEqual(i == 0 ? 1 : 0, CentredMod(product[i], 3), "p = " + p + ", coefficient " + i);
                    }
                }
                Assert.IsTrue(found > 0);
            }
        }

        [Test]
        public void TestSortUInt32()
        {
            var lengths = new List<int>();
            for (int n = 0; n <= 70; n++)
            {
                lengths.Add(n);
            }
            foreach (int[] pq in PQ)
            {
                lengths.Add(pq[0]);
            }

            uint[] extremes = { 0U, 1U, 0x7FFFFFFFU, 0x80000000U, 0x80000001U, 0xFFFFFFFEU, 0xFFFFFFFFU };

            foreach (int n in lengths)
            {
                for (int trial = 0; trial < 20; trial++)
                {
                    uint[] x = new uint[n];
                    for (int i = 0; i < n; i++)
                    {
                        switch (trial % 3)
                        {
                        case 0:
                            x[i] = NextUInt32();
                            break;
                        case 1:
                            // many duplicates
                            x[i] = (uint)m_random.Next(4) << 30 | (uint)m_random.Next(2);
                            break;
                        default:
                            x[i] = extremes[m_random.Next(extremes.Length)];
                            break;
                        }
                    }

                    uint[] expected = (uint[])x.Clone();
                    Array.Sort(expected);

                    NtruPrimeUtilities.SortUInt32(x);
                    Assert.AreEqual(expected, x, "n = " + n);
                }
            }
        }

        private static void CheckFreeze(int x, int n, int barrett)
        {
            int expected = CentredMod(x, n);
            int actual = NtruPrimeUtilities.Freeze(x, n, barrett);
            if (actual != expected)
            {
                Assert.Fail("Freeze(" + x + ", " + n + ") = " + actual + ", expected " + expected);
            }
        }

        private static void CheckRqMult(short[] f, sbyte[] g, int p, int q)
        {
            short[] h = new short[p];
            NtruPrimeUtilities.RqMult(h, f, g, p, q);

            long[] expected = ReferenceProduct(ToInts(f), ToInts(g), p);
            for (int i = 0; i < p; i++)
            {
                if (h[i] != CentredMod(expected[i], q))
                {
                    Assert.Fail("RqMult p = " + p + ", coefficient " + i + ": " + h[i] + ", expected "
                        + CentredMod(expected[i], q));
                }
            }
        }

        private static void CheckR3Mult(sbyte[] f, sbyte[] g, int p)
        {
            sbyte[] h = new sbyte[p];
            NtruPrimeUtilities.R3Mult(h, f, g, p);

            long[] expected = ReferenceProduct(ToInts(f), ToInts(g), p);
            for (int i = 0; i < p; i++)
            {
                if (h[i] != CentredMod(expected[i], 3))
                {
                    Assert.Fail("R3Mult p = " + p + ", coefficient " + i + ": " + h[i] + ", expected "
                        + CentredMod(expected[i], 3));
                }
            }
        }

        /// <summary>Schoolbook product modulo x^p - x - 1, exact in long arithmetic.</summary>
        private static long[] ReferenceProduct(int[] f, int[] g, int p)
        {
            long[] fg = new long[2 * p - 1];
            for (int i = 0; i < p; i++)
            {
                for (int j = 0; j < p; j++)
                {
                    fg[i + j] += (long)f[i] * g[j];
                }
            }
            for (int i = 2 * p - 2; i >= p; i--)
            {
                fg[i - p] += fg[i];
                fg[i - p + 1] += fg[i];
            }
            return fg;
        }

        /// <summary>x mod n in [-(n - 1) / 2, (n - 1) / 2].</summary>
        private static int CentredMod(long x, int n)
        {
            long r = x % n;
            if (r < 0)
            {
                r += n;
            }
            if (r > (n - 1) / 2)
            {
                r -= n;
            }
            return (int)r;
        }

        private static int[][] GetPQ()
        {
            var parameters = new List<int[]>();
            foreach (var s in new SNtruPrimeParameters[]{ SNtruPrimeParameters.sntrup653,
                SNtruPrimeParameters.sntrup761, SNtruPrimeParameters.sntrup857, SNtruPrimeParameters.sntrup953,
                SNtruPrimeParameters.sntrup1013, SNtruPrimeParameters.sntrup1277 })
            {
                AddPQ(parameters, s.P, s.Q);
            }
            foreach (var l in new NtruLPRimeParameters[]{ NtruLPRimeParameters.ntrulpr653,
                NtruLPRimeParameters.ntrulpr761, NtruLPRimeParameters.ntrulpr857, NtruLPRimeParameters.ntrulpr953,
                NtruLPRimeParameters.ntrulpr1013, NtruLPRimeParameters.ntrulpr1277 })
            {
                AddPQ(parameters, l.P, l.Q);
            }
            return parameters.ToArray();
        }

        private static void AddPQ(List<int[]> parameters, int p, int q)
        {
            foreach (int[] pq in parameters)
            {
                if (pq[0] == p && pq[1] == q)
                    return;
            }
            parameters.Add(new int[]{ p, q });
        }

        private uint NextUInt32()
        {
            return (uint)m_random.Next(1 << 16) << 16 | (uint)m_random.Next(1 << 16);
        }

        private static int[] ToInts(short[] s)
        {
            int[] r = new int[s.Length];
            for (int i = 0; i < s.Length; i++)
            {
                r[i] = s[i];
            }
            return r;
        }

        private static int[] ToInts(sbyte[] b)
        {
            int[] r = new int[b.Length];
            for (int i = 0; i < b.Length; i++)
            {
                r[i] = b[i];
            }
            return r;
        }
    }
}
