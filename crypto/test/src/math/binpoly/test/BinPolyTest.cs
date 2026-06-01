// BinPoly's surface is assembly-internal (closed for the squash/merge), so these direct tests
// can no longer reference it from the test assembly. Disabled via #if false (the code is kept
// for re-enabling if InternalsVisibleTo is ever added). Indirect coverage remains through the
// consumers (generic F2m field via ECPointTest; BIKE/HQC KATs).
#if false
using System;
using System.Diagnostics;

using NUnit.Framework;

using Org.BouncyCastle.Math.BinPoly;

namespace Org.BouncyCastle.Math.BinPoly.Tests
{
    /// <summary>
    /// Correctness tests and <c>[Explicit]</c> benchmarks for <see cref="IBinPolyMul"/>. Binomial
    /// coverage uses a BIKE-style ring (cyclic <c>GF(2)[x] / (x^r + 1)</c>); trinomial coverage
    /// uses the standardised SECT curve trinomials (sect113, sect193, sect233, sect239,
    /// sect409); pentanomial coverage uses the standardised SECT curve pentanomials (sect131,
    /// sect163, sect283, sect571). The oracle in each case is a small, obviously-correct
    /// shift-and-XOR reference reduction implemented inline below.
    /// </summary>
    [TestFixture]
    public class BinPolyTest
    {
        // BIKE-1 ring size (security level 1). Smallest of the BIKE parameter sets, used for speed.
        // BIKE-3 (24659) and BIKE-5 (40973) exist but aren't exercised in correctness tests here to
        // keep test runtime small; the BIKE-class binomial benchmarks below cover all three.
        private const int BikeR1 = 12323;
        private const int BikeR3 = 24659;
        private const int BikeR5 = 40973;
        private const int HqcR128 = 17669;
        private const int HqcR192 = 35851;
        private const int HqcR256 = 57637;

        // BIKE binomial ring sizes for benchmarking — the cyclic ring r-values used by the NIST
        // security level 1, 3, and 5 parameter sets. These are the typical workloads driving
        // BinPoly's Karatsuba multiply paths.
        private static readonly object[] BikeBinomials =
        {
            new object[] { "bike1", BikeR1 },
            new object[] { "bike3", BikeR3 },
            new object[] { "bike5", BikeR5 },
        };

        // Small odd-n binomials sized to exercise the specialized fixed-size CLMUL kernels
        // dispatched from public Multiply (ImplMul1, ImplMul2, ...). Each entry sits at the top
        // of its size bucket so any partial-limb tail also gets covered.
        private static readonly object[] SmallBinomials =
        {
            new object[] { "small_n_63",  63 },  // size = 1
            new object[] { "small_n127", 127 },  // size = 2
            new object[] { "small_n191", 191 },  // size = 3
            new object[] { "small_n255", 255 },  // size = 4
            new object[] { "small_n319", 319 },  // size = 5
            new object[] { "small_n383", 383 },  // size = 6
            new object[] { "small_n447", 447 },  // size = 7
            new object[] { "small_n511", 511 },  // size = 8
            new object[] { "small_n575", 575 },  // size = 9
            new object[] { "small_n639", 639 },  // size = 10
        };

        // Odd-n binomials sized to exercise the CLMUL Karatsuba cutoff region with size in [11, 32).
        private static readonly object[] MediumBinomials =
        {
            new object[] { "med_n_703",  703 },  // size = 11
            new object[] { "med_n_767",  767 },  // size = 12
            new object[] { "med_n_831",  831 },  // size = 13
            new object[] { "med_n_895",  895 },  // size = 14
            new object[] { "med_n_959",  959 },  // size = 15
            new object[] { "med_n1023", 1023 },  // size = 16
            new object[] { "med_n1087", 1087 },  // size = 17
            new object[] { "med_n1151", 1151 },  // size = 18
            new object[] { "med_n1215", 1215 },  // size = 19
            new object[] { "med_n1279", 1279 },  // size = 20
            new object[] { "med_n1343", 1343 },  // size = 21
            new object[] { "med_n1407", 1407 },  // size = 22
            new object[] { "med_n1471", 1471 },  // size = 23
            new object[] { "med_n1535", 1535 },  // size = 24
            new object[] { "med_n1599", 1599 },  // size = 25
            new object[] { "med_n1663", 1663 },  // size = 26
            new object[] { "med_n1727", 1727 },  // size = 27
            new object[] { "med_n1791", 1791 },  // size = 28
            new object[] { "med_n1855", 1855 },  // size = 29
            new object[] { "med_n1919", 1919 },  // size = 30
            new object[] { "med_n1983", 1983 },  // size = 31
        };

        // Even-n binomials. No standardised binomial consumer has even n (BIKE/HQC rings are
        // prime), so this is correctness-defensive coverage of the lifted odd-n restriction.
        // The (n & 63) != 0 cases route to BinomialReduce.Unaligned (partial top limb); the
        // n-multiple-of-64 cases route to the word-aligned BinomialReduce.Aligned (z = low ^ high).
        private static readonly object[] EvenBinomials =
        {
            new object[] { "evenBin_n_66",  66 },   // size = 2, s_n = 2
            new object[] { "evenBin_n_96",  96 },   // size = 2, s_n = 32
            new object[] { "evenBin_n130", 130 },   // size = 3, s_n = 2
            new object[] { "evenBin_n160", 160 },   // size = 3, s_n = 32
            new object[] { "evenBin_n_64",  64 },   // size = 1, word-aligned
            new object[] { "evenBin_n128", 128 },   // size = 2, word-aligned
            new object[] { "evenBin_n256", 256 },   // size = 4, word-aligned
            new object[] { "evenBin_n512", 512 },   // size = 8, word-aligned
        };

        // Reduction polynomials of the irreducible-trinomial SECT curves. Each entry is
        // (label, n, k) describing x^n + x^k + 1. Maps to TrinomialReduce sub-cases as:
        // sect113 -> A4 (size-2 non-slack unroll, n in [97, 127]), sect193 -> A7 (size-4
        // slack unroll, n in [193, 223]), sect233 and sect239 -> C8 (size-4 non-slack
        // unroll, n in [225, 255]), sect409 -> C (general). Sub-cases A3 (size-2 slack,
        // n in [65, 95]), A5 (size-3 slack, n in [129, 159]), A6 (size-3, n in [161,
        // 191]), A8 (size-4 non-slack, n in [225, 255]), C5 (size-3 slack, n in [129,
        // 159]), C6 (size-3, n in [161, 191]), C7 (size-4 slack, n in [193, 223]), B (k a
        // multiple of 64), D (n - k < 64), and A's w_n >= 4 inter-iteration register-carry
        // branch are covered by the synthetic data sources below.
        private static readonly object[] SectTrinomials =
        {
            new object[] { "sect113", 113, 9 },
            new object[] { "sect193", 193, 15 },
            new object[] { "sect233", 233, 74 },
            new object[] { "sect239", 239, 158 },
            new object[] { "sect409", 409, 87 },
        };

        // Synthetic trinomials exercising the inter-iteration register-carry path of
        // TrinomialReduce.A (w_n >= 4, k < 64, n - k >= 64, n & 63 != 0). The picks span
        // small / medium / large w_n so savings can be tracked as a function of loop length
        // when used by the benchmarks. Irreducibility is not required — only the (n, k)
        // layout matters to the reducer.
        private static readonly object[] SyntheticTrinomialsA =
        {
            new object[] { "trinA_n257_k1",  257,  1 },   // w_n = 4, s_n = 1
            new object[] { "trinA_n383_k29", 383, 29 },   // w_n = 5
            new object[] { "trinA_n767_k7",  767,  7 },   // w_n = 11
        };

        // Synthetic trinomials exercising TrinomialReduce.A3 (size-2 unroll with tt[3]
        // slack-elided, n in [65, 95], k < 64, n - k >= 64). No SECT trinomial hits this
        // branch. Cases span the s_n extremes within the A3 range.
        private static readonly object[] SyntheticTrinomialsA3 =
        {
            new object[] { "trinA3_n65_k1", 65,  1 },   // smallest (w_n=1, s_n=1)
            new object[] { "trinA3_n95_k1", 95,  1 },   // largest  (w_n=1, s_n=31)
        };

        // Synthetic trinomials exercising TrinomialReduce.A5 (size-3 unroll with tt[5]
        // slack-elided, n in [129, 159], k < 64, n - k >= 64). No SECT trinomial hits
        // this branch. Cases span the s_n extremes within the A5 range.
        private static readonly object[] SyntheticTrinomialsA5 =
        {
            new object[] { "trinA5_n129_k1", 129,  1 },   // smallest (w_n=2, s_n=1)
            new object[] { "trinA5_n159_k1", 159,  1 },   // largest  (w_n=2, s_n=31)
        };

        // Synthetic trinomials exercising TrinomialReduce.A6 (size-3 unroll, w_n == 2,
        // n in [161, 191], k < 64, n - k >= 64). No SECT trinomial hits this branch.
        // Cases span the s_n extremes within the A6 range.
        private static readonly object[] SyntheticTrinomialsA6 =
        {
            new object[] { "trinA6_n161_k1", 161,  1 },   // smallest (w_n=2, s_n=33)
            new object[] { "trinA6_n191_k5", 191,  5 },   // largest  (w_n=2, s_n=63)
        };

        // Synthetic trinomials exercising TrinomialReduce.A8 (size-4 unroll, w_n == 3,
        // n in [225, 255], k < 64, n - k >= 64). No SECT trinomial hits this branch.
        // Cases span the s_n extremes within the A8 range.
        private static readonly object[] SyntheticTrinomialsA8 =
        {
            new object[] { "trinA8_n225_k1", 225,  1 },   // smallest (w_n=3, s_n=33)
            new object[] { "trinA8_n255_k5", 255,  5 },   // largest  (w_n=3, s_n=63)
        };

        // Synthetic trinomials exercising TrinomialReduce sub-case B (k a multiple of 64,
        // k >= 64, n - k >= 64). No SECT trinomial hits this branch. The "+x^k" tap is
        // word-aligned so the reducer skips the cross-word splice; cases vary w_k (the
        // k-in-words offset) to probe more than one alignment.
        private static readonly object[] SyntheticTrinomialsB =
        {
            new object[] { "trinB_n129_k64",  129,  64 },   // w_n = 2, w_k = 1
            new object[] { "trinB_n257_k128", 257, 128 },   // w_n = 4, w_k = 2
            new object[] { "trinB_n513_k128", 513, 128 },   // w_n = 8, w_k = 2
        };

        // Synthetic trinomials exercising TrinomialReduce.C5 (size-3 unroll with tt[5]
        // slack-elided, n in [129, 159], k >= 64 with (k & 63) != 0, n - k >= 64 forces
        // w_k = 1). No SECT trinomial hits this branch.
        private static readonly object[] SyntheticTrinomialsC5 =
        {
            new object[] { "trinC5_n129_k65", 129, 65 },   // smallest (w_n=2, s_n=1, w_k=1)
            new object[] { "trinC5_n159_k95", 159, 95 },   // largest  (w_n=2, s_n=31, w_k=1)
        };

        // Synthetic trinomials exercising TrinomialReduce.C6 (size-3 unroll, w_n == 2,
        // n in [161, 191], k >= 64 with (k & 63) != 0, n - k >= 64 forces w_k = 1). No
        // SECT trinomial hits this branch.
        private static readonly object[] SyntheticTrinomialsC6 =
        {
            new object[] { "trinC6_n161_k65",  161,  65 },   // smallest (w_n=2, s_n=33, w_k=1)
            new object[] { "trinC6_n191_k127", 191, 127 },   // largest  (w_n=2, s_n=63, w_k=1)
        };

        // Synthetic trinomials exercising TrinomialReduce.C7 (size-4 unroll with tt[7]
        // slack-elided, n in [193, 223], k >= 64 with (k & 63) != 0, n - k >= 64). Cases
        // cover both w_k branches (w_k in {1, 2}). No SECT trinomial hits this branch.
        private static readonly object[] SyntheticTrinomialsC7 =
        {
            new object[] { "trinC7_n193_k65",  193,  65 },   // w_k=1 (smallest)
            new object[] { "trinC7_n223_k159", 223, 159 },   // w_k=2 (largest n with w_k=2)
        };

        // Synthetic trinomials exercising TrinomialReduce sub-case D (n - k < 64). No SECT
        // trinomial hits this branch; D is a bit-by-bit correctness fallback for the
        // pathological case where a word-at-a-time "+x^k" tap would spill above n.
        private static readonly object[] SyntheticTrinomialsD =
        {
            new object[] { "trinD_n65_k2",    65,   2 },   // n - k = 63
            new object[] { "trinD_n127_k70", 127,  70 },   // n - k = 57
            new object[] { "trinD_n193_k140", 193, 140 },  // n - k = 53
        };

        // Even-n trinomials. No standardised trinomial consumer has even n (X9.62 c2tnb* and SECT
        // m's are odd), so this is correctness-defensive coverage of the lifted odd-n restriction.
        // (n & 63) != 0 cases exercise the word-at-a-time families with even n (A5, A6, C7);
        // word-aligned n routes to the word-aligned fold E ((k & 63) != 0, n - k >= 64) or the
        // bitwise reducer D (k a multiple of 64, or n - k < 64). Irreducibility is not required.
        private static readonly object[] EvenTrinomials =
        {
            new object[] { "evenTrin_n130_k5",   130,   5 },   // s_n != 0 -> A5
            new object[] { "evenTrin_n160_k7",   160,   7 },   // s_n != 0 -> A6
            new object[] { "evenTrin_n200_k70",  200,  70 },   // s_n != 0 -> C7
            new object[] { "evenTrin_n64_k5",     64,   5 },   // word-aligned, n - k < 64 -> D
            new object[] { "evenTrin_n128_k64",  128,  64 },   // word-aligned, k mult of 64 -> D
            new object[] { "evenTrin_n128_k7",   128,   7 },   // word-aligned -> E (w_k = 0)
            new object[] { "evenTrin_n192_k65",  192,  65 },   // word-aligned -> E (w_k = 1)
            new object[] { "evenTrin_n256_k9",   256,   9 },   // word-aligned -> E (w_k = 0)
            new object[] { "evenTrin_n256_k127", 256, 127 },   // word-aligned -> E (w_k = 1, s_k = 63)
        };

        // Reduction polynomials of the irreducible-pentanomial SECT curves. Each entry is
        // (label, n, k1, k2, k3) describing x^n + x^k3 + x^k2 + x^k1 + 1 with 0 < k1 < k2 < k3 < n.
        // Maps to PentanomialReduce sub-cases as: sect131 -> A5 (size-3 slack unroll, n in
        // [129, 159]), sect163 -> A6 (size-3 unroll, n in [161, 191]), sect283 / sect571 ->
        // A (general, w_n >= 4). Sub-cases A3 (size-2 slack, n in [67, 95]), A4 (size-2,
        // n in [97, 127]), A7 (size-4 slack, n in [193, 223]), A8 (size-4, n in [225, 255]),
        // B (k2 > 64), C (catch-all), D (k2 < 64, k3 >= 64) are covered by the synthetic
        // data sources below.
        private static readonly object[] SectPentanomials =
        {
            new object[] { "sect131", 131, 2, 3,  8 },
            new object[] { "sect163", 163, 3, 6,  7 },
            new object[] { "sect283", 283, 5, 7, 12 },
            new object[] { "sect571", 571, 2, 5, 10 },
        };

        // Synthetic pentanomials exercising PentanomialReduce.A3 (size-2 unroll with tt[3]
        // slack-elided, n in [67, 95], all k_i < 64, n - k3 >= 64). No SECT pentanomial
        // hits this branch.
        private static readonly object[] SyntheticPentanomialsA3 =
        {
            new object[] { "pentaA3_n67_k1_2_3",    67,  1,  2,  3 },   // smallest (w_n=1, s_n=3)
            new object[] { "pentaA3_n95_k15_25_31", 95, 15, 25, 31 },   // largest  (w_n=1, s_n=31)
        };

        // Synthetic pentanomials exercising PentanomialReduce.A4 (size-2 unroll, n in
        // [97, 127], all k_i < 64, n - k3 >= 64). No SECT pentanomial hits this branch.
        private static readonly object[] SyntheticPentanomialsA4 =
        {
            new object[] { "pentaA4_n97_k1_2_3",     97,  1,  2,  3 },   // smallest (w_n=1, s_n=33)
            new object[] { "pentaA4_n127_k5_20_63", 127,  5, 20, 63 },   // largest  (w_n=1, s_n=63)
        };

        // Synthetic pentanomials exercising PentanomialReduce.A7 (size-4 unroll with tt[7]
        // slack-elided, n in [193, 223], all k_i < 64, n - k3 >= 64). No SECT pentanomial
        // hits this branch.
        private static readonly object[] SyntheticPentanomialsA7 =
        {
            new object[] { "pentaA7_n193_k1_2_3",    193,  1,  2,  3 },   // smallest (w_n=3, s_n=1)
            new object[] { "pentaA7_n223_k30_50_63", 223, 30, 50, 63 },   // largest  (w_n=3, s_n=31)
        };

        // Synthetic pentanomials exercising PentanomialReduce.A8 (size-4 unroll, n in
        // [225, 255], all k_i < 64, n - k3 >= 64). No SECT pentanomial hits this branch.
        private static readonly object[] SyntheticPentanomialsA8 =
        {
            new object[] { "pentaA8_n225_k1_2_3",    225,  1,  2,  3 },   // smallest (w_n=3, s_n=33)
            new object[] { "pentaA8_n255_k5_20_63",  255,  5, 20, 63 },   // largest  (w_n=3, s_n=63)
        };

        // Synthetic pentanomials exercising PentanomialReduce sub-case B (k2 >= 64, all
        // (k_i & 63) != 0, n - k3 >= 64). No SECT pentanomial hits this branch. Each "+x^ki"
        // tap with k_i >= 64 straddles a word boundary so the reducer uses the modular-shift
        // splice.
        private static readonly object[] SyntheticPentanomialsB =
        {
            new object[] { "pentaB_n193_k1_65_67",    193,  1, 65,  67 },
            new object[] { "pentaB_n513_k10_70_200",  513, 10, 70, 200 },
            new object[] { "pentaB_n513_k63_70_300",  513, 63, 70, 300 },
        };

        // Synthetic pentanomials exercising PentanomialReduce sub-case C, the catch-all
        // (n - k3 < 64, or k3 a multiple of 64, or k2 >= 64 with some k_i a multiple of 64).
        // No SECT pentanomial hits this branch. Cases cover both dispatch flavours: the
        // n - k3 < 64 path (bit-by-bit needed because a "+x^ki" tap could spill above n) and
        // the word-aligned-k_i path (one or more k_i a multiple of 64).
        private static readonly object[] SyntheticPentanomialsC =
        {
            new object[] { "pentaC_n129_k1_2_66",     129,  1,  2,  66 },  // n - k3 = 63
            new object[] { "pentaC_n193_k1_2_64",     193,  1,  2,  64 },  // k3 mult of 64
            new object[] { "pentaC_n257_k64_65_130",  257, 64, 65, 130 },  // k1 mult of 64
        };

        // Synthetic pentanomials exercising PentanomialReduce sub-case D (k2 < 64, k3 >= 64
        // with (k3 & 63) != 0, n - k3 >= 64). No SECT pentanomial hits this branch. The
        // "+x^k1" and "+x^k2" taps fuse into A-style word-aligned writes; only the "+x^k3"
        // tap uses the modular-shift splice. Minimum n in this domain is 129 (w_n >= 2).
        private static readonly object[] SyntheticPentanomialsD =
        {
            new object[] { "pentaD_n129_k1_2_65",     129,  1,  2,  65 },  // smallest (w_n=2)
            new object[] { "pentaD_n257_k3_33_130",   257,  3, 33, 130 },
            new object[] { "pentaD_n513_k10_63_200",  513, 10, 63, 200 },
        };

        // Reduction polynomials of the standardised X9.62 c2pnb* binary curves, which have even m.
        // Each entry is (label, n, k1, k2, k3) describing x^n + x^k3 + x^k2 + x^k1 + 1. These are
        // the real-world motivation for lifting the odd-n restriction; all have (n & 63) != 0 and
        // route to the existing word-at-a-time pentanomial reducers with even n:
        // c2pnb176w1 -> A6, c2pnb272w1 / c2pnb304w1 -> A (general), c2pnb208w1 / c2pnb368w1 -> D.
        // Parameters from Org.BouncyCastle.Asn1.X9.X962NamedCurves.
        private static readonly object[] X962EvenPentanomials =
        {
            new object[] { "c2pnb176w1", 176, 1, 2, 43 },   // s_n = 48 -> A6
            new object[] { "c2pnb208w1", 208, 1, 2, 83 },   // s_n = 16 -> D
            new object[] { "c2pnb272w1", 272, 1, 3, 56 },   // s_n = 16 -> A (general)
            new object[] { "c2pnb304w1", 304, 1, 2, 11 },   // s_n = 48 -> A (general)
            new object[] { "c2pnb368w1", 368, 1, 2, 85 },   // s_n = 48 -> D
        };

        // Synthetic n-multiple-of-64 pentanomials. No standardised curve has m a multiple of 64,
        // so this is correctness-defensive coverage of the word-aligned dispatch: the word-aligned
        // fold E (all (k_i & 63) != 0 and n - k3 >= 64) and the bitwise reducer C (the residual
        // cases). Irreducibility is not required.
        private static readonly object[] MultOf64Pentanomials =
        {
            new object[] { "penta64_n64_k1_2_3",      64,  1,  2,   3 },   // n - k3 < 64 -> C
            new object[] { "penta64_n128_k2_5_7",    128,  2,  5,   7 },   // -> E (w_ki = 0)
            new object[] { "penta64_n256_k5_7_12",   256,  5,  7,  12 },   // -> E (w_ki = 0)
            new object[] { "penta64_n256_k1_65_130", 256,  1, 65, 130 },   // -> E (w_k2 = 1, w_k3 = 2)
            new object[] { "penta64_n256_k1_64_130", 256,  1, 64, 130 },   // k2 mult of 64 -> C
        };

        private const int RandomTrials = 16;
        private const int FixedSeed = 0x10101010;

        [Test]
        public void Binomial_Add_AgainstXor_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, BikeR1);
                ulong[] y = RandomReduced(random, BikeR1);
                ulong[] z = BinPolys.Create(binomial.Size);

                BinPolys.Add(binomial.Size, x, 0, y, 0, z, 0);

                for (int i = 0; i < binomial.Size; ++i)
                {
                    Assert.AreEqual(x[i] ^ y[i], z[i], "Add at limb " + i);
                }
            }
        }

        [Test]
        public void Binomial_AddTo_AgainstXor_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed + 1);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, BikeR1);
                ulong[] z = RandomReduced(random, BikeR1);
                ulong[] expected = new ulong[binomial.Size];
                for (int i = 0; i < binomial.Size; ++i)
                {
                    expected[i] = x[i] ^ z[i];
                }

                BinPolys.AddTo(binomial.Size, x, 0, z, 0);

                Assert.AreEqual(expected, z);
            }
        }

        [Test]
        public void Binomial_Multiply_AgainstReference_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed + 2);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, BikeR1);
                ulong[] y = RandomReduced(random, BikeR1);
                ulong[] z = BinPolys.Create(binomial.Size);

                binomial.Multiply(x, 0, y, 0, z, 0);

                ulong[] expected = ReferenceBinomialMul(BikeR1, x, y);
                Assert.AreEqual(expected, z, "trial " + t);
            }
        }

        [TestCaseSource(nameof(EvenBinomials))]
        [TestCaseSource(nameof(SmallBinomials))]
        public void Binomial_Multiply_AgainstReference_Small(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var random = new Random(FixedSeed + n);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] y = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(binomial.Size);

                binomial.Multiply(x, 0, y, 0, z, 0);

                ulong[] expected = ReferenceBinomialMul(n, x, y);
                Assert.AreEqual(expected, z, label + " trial " + t);
            }
        }

        [TestCaseSource(nameof(EvenBinomials))]
        public void Binomial_Square_AgainstReference_Even(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var random = new Random(FixedSeed + n);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(binomial.Size);

                binomial.Square(x, 0, z, 0);

                ulong[] expected = ReferenceBinomialMul(n, x, x);
                Assert.AreEqual(expected, z, label + " trial " + t);
            }
        }

        [Test]
        public void Binomial_Multiply_MultiplyByZero_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed + 3);

            ulong[] x = RandomReduced(random, BikeR1);
            ulong[] zero = BinPolys.Create(binomial.Size);
            ulong[] z = BinPolys.Create(binomial.Size);

            binomial.Multiply(x, 0, zero, 0, z, 0);

            Assert.AreEqual(zero, z);
        }

        [Test]
        public void Binomial_Multiply_MultiplyByOne_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed + 4);

            ulong[] x = RandomReduced(random, BikeR1);
            ulong[] one = BinPolys.Create(binomial.Size);
            one[0] = 1UL;
            ulong[] z = BinPolys.Create(binomial.Size);

            binomial.Multiply(x, 0, one, 0, z, 0);

            Assert.AreEqual(x, z);
        }

        [Test]
        public void Binomial_Square_AgainstReferenceMultiplyBySelf_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed + 5);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, BikeR1);
                ulong[] z = BinPolys.Create(binomial.Size);

                binomial.Square(x, 0, z, 0);

                ulong[] expected = ReferenceBinomialMul(BikeR1, x, x);
                Assert.AreEqual(expected, z, "trial " + t);
            }
        }

        [Test]
        public void Binomial_SquareN_AgainstRepeatedSquare_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            var random = new Random(FixedSeed + 6);
            int[] ns = { 1, 2, 3, 7, 16 };

            foreach (int n in ns)
            {
                ulong[] x = RandomReduced(random, BikeR1);
                ulong[] z = BinPolys.Create(binomial.Size);
                binomial.SquareN(x, 0, n, z, 0);

                ulong[] expected = BinPolys.Create(binomial.Size);
                binomial.Square(x, 0, expected, 0);
                for (int i = 1; i < n; ++i)
                {
                    binomial.Square(expected, 0, expected, 0);
                }

                Assert.AreEqual(expected, z, "n = " + n);
            }
        }

        [Test]
        public void Binomial_SquareN_ZeroNThrows_BikeR1()
        {
            var binomial = BinPolys.Mul.Binomial(BikeR1);
            ulong[] x = BinPolys.Create(binomial.Size);
            ulong[] z = BinPolys.Create(binomial.Size);

            Assert.Throws<ArgumentOutOfRangeException>(() => binomial.SquareN(x, 0, 0, z, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => binomial.SquareN(x, 0, -1, z, 0));
        }

        [TestCaseSource(nameof(EvenTrinomials))]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        [TestCaseSource(nameof(SyntheticTrinomialsA3))]
        [TestCaseSource(nameof(SyntheticTrinomialsA5))]
        [TestCaseSource(nameof(SyntheticTrinomialsA6))]
        [TestCaseSource(nameof(SyntheticTrinomialsA8))]
        [TestCaseSource(nameof(SyntheticTrinomialsB))]
        [TestCaseSource(nameof(SyntheticTrinomialsC5))]
        [TestCaseSource(nameof(SyntheticTrinomialsC6))]
        [TestCaseSource(nameof(SyntheticTrinomialsC7))]
        [TestCaseSource(nameof(SyntheticTrinomialsD))]
        public void Trinomial_Multiply_AgainstReference(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var random = new Random(FixedSeed + 100 + n);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] y = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(trinomial.Size);

                trinomial.Multiply(x, 0, y, 0, z, 0);

                ulong[] expected = ReferenceTrinomialMul(n, k, x, y);
                Assert.AreEqual(expected, z, label + " trial " + t);
            }
        }

        [TestCaseSource(nameof(EvenTrinomials))]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        [TestCaseSource(nameof(SyntheticTrinomialsA3))]
        [TestCaseSource(nameof(SyntheticTrinomialsA5))]
        [TestCaseSource(nameof(SyntheticTrinomialsA6))]
        [TestCaseSource(nameof(SyntheticTrinomialsA8))]
        [TestCaseSource(nameof(SyntheticTrinomialsB))]
        [TestCaseSource(nameof(SyntheticTrinomialsC5))]
        [TestCaseSource(nameof(SyntheticTrinomialsC6))]
        [TestCaseSource(nameof(SyntheticTrinomialsC7))]
        [TestCaseSource(nameof(SyntheticTrinomialsD))]
        public void Trinomial_Multiply_MultiplyByZero(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var random = new Random(FixedSeed + 200 + n);

            ulong[] x = RandomReduced(random, n);
            ulong[] zero = BinPolys.Create(trinomial.Size);
            ulong[] z = BinPolys.Create(trinomial.Size);

            trinomial.Multiply(x, 0, zero, 0, z, 0);

            Assert.AreEqual(zero, z, label);
        }

        [TestCaseSource(nameof(EvenTrinomials))]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        [TestCaseSource(nameof(SyntheticTrinomialsA3))]
        [TestCaseSource(nameof(SyntheticTrinomialsA5))]
        [TestCaseSource(nameof(SyntheticTrinomialsA6))]
        [TestCaseSource(nameof(SyntheticTrinomialsA8))]
        [TestCaseSource(nameof(SyntheticTrinomialsB))]
        [TestCaseSource(nameof(SyntheticTrinomialsC5))]
        [TestCaseSource(nameof(SyntheticTrinomialsC6))]
        [TestCaseSource(nameof(SyntheticTrinomialsC7))]
        [TestCaseSource(nameof(SyntheticTrinomialsD))]
        public void Trinomial_Multiply_MultiplyByOne(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var random = new Random(FixedSeed + 300 + n);

            ulong[] x = RandomReduced(random, n);
            ulong[] one = BinPolys.Create(trinomial.Size);
            one[0] = 1UL;
            ulong[] z = BinPolys.Create(trinomial.Size);

            trinomial.Multiply(x, 0, one, 0, z, 0);

            Assert.AreEqual(x, z, label);
        }

        [TestCaseSource(nameof(EvenTrinomials))]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        [TestCaseSource(nameof(SyntheticTrinomialsA3))]
        [TestCaseSource(nameof(SyntheticTrinomialsA5))]
        [TestCaseSource(nameof(SyntheticTrinomialsA6))]
        [TestCaseSource(nameof(SyntheticTrinomialsA8))]
        [TestCaseSource(nameof(SyntheticTrinomialsB))]
        [TestCaseSource(nameof(SyntheticTrinomialsC5))]
        [TestCaseSource(nameof(SyntheticTrinomialsC6))]
        [TestCaseSource(nameof(SyntheticTrinomialsC7))]
        [TestCaseSource(nameof(SyntheticTrinomialsD))]
        public void Trinomial_Square_AgainstReferenceMultiplyBySelf(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var random = new Random(FixedSeed + 400 + n);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(trinomial.Size);

                trinomial.Square(x, 0, z, 0);

                ulong[] expected = ReferenceTrinomialMul(n, k, x, x);
                Assert.AreEqual(expected, z, label + " trial " + t);
            }
        }

        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        [TestCaseSource(nameof(SyntheticTrinomialsA3))]
        [TestCaseSource(nameof(SyntheticTrinomialsA5))]
        [TestCaseSource(nameof(SyntheticTrinomialsA6))]
        [TestCaseSource(nameof(SyntheticTrinomialsA8))]
        [TestCaseSource(nameof(SyntheticTrinomialsB))]
        [TestCaseSource(nameof(SyntheticTrinomialsC5))]
        [TestCaseSource(nameof(SyntheticTrinomialsC6))]
        [TestCaseSource(nameof(SyntheticTrinomialsC7))]
        [TestCaseSource(nameof(SyntheticTrinomialsD))]
        [TestCaseSource(nameof(EvenTrinomials))]
        public void Trinomial_SquareN_AgainstRepeatedSquare(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var random = new Random(FixedSeed + 500 + n);
            int[] sns = { 1, 2, 3, 7, 16 };

            foreach (int sn in sns)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(trinomial.Size);
                trinomial.SquareN(x, 0, sn, z, 0);

                ulong[] expected = BinPolys.Create(trinomial.Size);
                trinomial.Square(x, 0, expected, 0);
                for (int i = 1; i < sn; ++i)
                {
                    trinomial.Square(expected, 0, expected, 0);
                }

                Assert.AreEqual(expected, z, label + " sn = " + sn);
            }
        }

        [TestCaseSource(nameof(MultOf64Pentanomials))]
        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(SyntheticPentanomialsA3))]
        [TestCaseSource(nameof(SyntheticPentanomialsA4))]
        [TestCaseSource(nameof(SyntheticPentanomialsA7))]
        [TestCaseSource(nameof(SyntheticPentanomialsA8))]
        [TestCaseSource(nameof(SyntheticPentanomialsB))]
        [TestCaseSource(nameof(SyntheticPentanomialsC))]
        [TestCaseSource(nameof(SyntheticPentanomialsD))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_Multiply_AgainstReference(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var random = new Random(FixedSeed + 600 + n);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] y = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(pentanomial.Size);

                pentanomial.Multiply(x, 0, y, 0, z, 0);

                ulong[] expected = ReferencePentanomialMul(n, k1, k2, k3, x, y);
                Assert.AreEqual(expected, z, label + " trial " + t);
            }
        }

        [TestCaseSource(nameof(MultOf64Pentanomials))]
        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(SyntheticPentanomialsA3))]
        [TestCaseSource(nameof(SyntheticPentanomialsA4))]
        [TestCaseSource(nameof(SyntheticPentanomialsA7))]
        [TestCaseSource(nameof(SyntheticPentanomialsA8))]
        [TestCaseSource(nameof(SyntheticPentanomialsB))]
        [TestCaseSource(nameof(SyntheticPentanomialsC))]
        [TestCaseSource(nameof(SyntheticPentanomialsD))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_Multiply_MultiplyByZero(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var random = new Random(FixedSeed + 700 + n);

            ulong[] x = RandomReduced(random, n);
            ulong[] zero = BinPolys.Create(pentanomial.Size);
            ulong[] z = BinPolys.Create(pentanomial.Size);

            pentanomial.Multiply(x, 0, zero, 0, z, 0);

            Assert.AreEqual(zero, z, label);
        }

        [TestCaseSource(nameof(MultOf64Pentanomials))]
        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(SyntheticPentanomialsA3))]
        [TestCaseSource(nameof(SyntheticPentanomialsA4))]
        [TestCaseSource(nameof(SyntheticPentanomialsA7))]
        [TestCaseSource(nameof(SyntheticPentanomialsA8))]
        [TestCaseSource(nameof(SyntheticPentanomialsB))]
        [TestCaseSource(nameof(SyntheticPentanomialsC))]
        [TestCaseSource(nameof(SyntheticPentanomialsD))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_Multiply_MultiplyByOne(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var random = new Random(FixedSeed + 800 + n);

            ulong[] x = RandomReduced(random, n);
            ulong[] one = BinPolys.Create(pentanomial.Size);
            one[0] = 1UL;
            ulong[] z = BinPolys.Create(pentanomial.Size);

            pentanomial.Multiply(x, 0, one, 0, z, 0);

            Assert.AreEqual(x, z, label);
        }

        [TestCaseSource(nameof(MultOf64Pentanomials))]
        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(SyntheticPentanomialsA3))]
        [TestCaseSource(nameof(SyntheticPentanomialsA4))]
        [TestCaseSource(nameof(SyntheticPentanomialsA7))]
        [TestCaseSource(nameof(SyntheticPentanomialsA8))]
        [TestCaseSource(nameof(SyntheticPentanomialsB))]
        [TestCaseSource(nameof(SyntheticPentanomialsC))]
        [TestCaseSource(nameof(SyntheticPentanomialsD))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_Square_AgainstReferenceMultiplyBySelf(string label, int n, int k1, int k2,
            int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var random = new Random(FixedSeed + 900 + n);

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(pentanomial.Size);

                pentanomial.Square(x, 0, z, 0);

                ulong[] expected = ReferencePentanomialMul(n, k1, k2, k3, x, x);
                Assert.AreEqual(expected, z, label + " trial " + t);
            }
        }

        [TestCaseSource(nameof(MultOf64Pentanomials))]
        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(SyntheticPentanomialsA3))]
        [TestCaseSource(nameof(SyntheticPentanomialsA4))]
        [TestCaseSource(nameof(SyntheticPentanomialsA7))]
        [TestCaseSource(nameof(SyntheticPentanomialsA8))]
        [TestCaseSource(nameof(SyntheticPentanomialsB))]
        [TestCaseSource(nameof(SyntheticPentanomialsC))]
        [TestCaseSource(nameof(SyntheticPentanomialsD))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_SquareN_AgainstRepeatedSquare(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var random = new Random(FixedSeed + 1000 + n);
            int[] sns = { 1, 2, 3, 7, 16 };

            foreach (int sn in sns)
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] z = BinPolys.Create(pentanomial.Size);
                pentanomial.SquareN(x, 0, sn, z, 0);

                ulong[] expected = BinPolys.Create(pentanomial.Size);
                pentanomial.Square(x, 0, expected, 0);
                for (int i = 1; i < sn; ++i)
                {
                    pentanomial.Square(expected, 0, expected, 0);
                }

                Assert.AreEqual(expected, z, label + " sn = " + sn);
            }
        }

        // ----- Non-zero-offset coverage -----

        // Distinct, mutually-prime offsets so any "wrong offset variable used" bug surfaces.
        // The reducer-body propagation (z[i] -> z[zOff + i], tt[i] -> tt[ttOff + i]) was a
        // mechanical pass across 25 classes; these tests confirm each reducer's body still
        // writes only inside its slice and reads only inside its window.
        private const int OffX = 3;
        private const int OffY = 5;
        private const int OffZ = 7;
        private const int OffPadTail = 4;

        [TestCaseSource(nameof(EvenBinomials))]
        [TestCaseSource(nameof(MediumBinomials))]
        [TestCaseSource(nameof(SmallBinomials))]
        public void Binomial_AllOps_NonZeroOffsets(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var random = new Random(FixedSeed + 1100 + n);
            RunAllOpsAtOffsets(binomial, n, random, label);
        }

        [TestCaseSource(nameof(EvenTrinomials))]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        [TestCaseSource(nameof(SyntheticTrinomialsA3))]
        [TestCaseSource(nameof(SyntheticTrinomialsA5))]
        [TestCaseSource(nameof(SyntheticTrinomialsA6))]
        [TestCaseSource(nameof(SyntheticTrinomialsA8))]
        [TestCaseSource(nameof(SyntheticTrinomialsB))]
        [TestCaseSource(nameof(SyntheticTrinomialsC5))]
        [TestCaseSource(nameof(SyntheticTrinomialsC6))]
        [TestCaseSource(nameof(SyntheticTrinomialsC7))]
        [TestCaseSource(nameof(SyntheticTrinomialsD))]
        public void Trinomial_AllOps_NonZeroOffsets(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var random = new Random(FixedSeed + 1200 + n);
            RunAllOpsAtOffsets(trinomial, n, random, label);
        }

        [TestCaseSource(nameof(MultOf64Pentanomials))]
        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(SyntheticPentanomialsA3))]
        [TestCaseSource(nameof(SyntheticPentanomialsA4))]
        [TestCaseSource(nameof(SyntheticPentanomialsA7))]
        [TestCaseSource(nameof(SyntheticPentanomialsA8))]
        [TestCaseSource(nameof(SyntheticPentanomialsB))]
        [TestCaseSource(nameof(SyntheticPentanomialsC))]
        [TestCaseSource(nameof(SyntheticPentanomialsD))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_AllOps_NonZeroOffsets(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var random = new Random(FixedSeed + 1300 + n);
            RunAllOpsAtOffsets(pentanomial, n, random, label);
        }

        // Runs every IBinPolyMul op (Multiply, Square, SquareN, Add, AddTo) at non-zero offsets,
        // each against the matching offset-zero baseline, with random-sentinel-filled guard
        // zones around every slice to catch off-by-one writes.
        private static void RunAllOpsAtOffsets(IBinPolyMul poly, int n, Random random, string label)
        {
            int size = poly.Size;

            // --- Multiply ---
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] y = RandomReduced(random, n);
                ulong[] zRef = BinPolys.Create(poly.Size);
                poly.Multiply(x, 0, y, 0, zRef, 0);

                ulong[] xBuf = PadBuffer(size, OffX, OffPadTail, random);
                ulong[] yBuf = PadBuffer(size, OffY, OffPadTail, random);
                ulong[] zBuf = PadBuffer(size, OffZ, OffPadTail, random);
                Array.Copy(x, 0, xBuf, OffX, size);
                Array.Copy(y, 0, yBuf, OffY, size);
                ulong[] xBufBefore = (ulong[])xBuf.Clone();
                ulong[] yBufBefore = (ulong[])yBuf.Clone();
                ulong[] zBufBefore = (ulong[])zBuf.Clone();

                poly.Multiply(xBuf, OffX, yBuf, OffY, zBuf, OffZ);

                AssertSliceEquals(zRef, zBuf, OffZ, size, label + " Multiply");
                Assert.AreEqual(xBufBefore, xBuf, label + " Multiply xBuf clobbered");
                Assert.AreEqual(yBufBefore, yBuf, label + " Multiply yBuf clobbered");
                AssertGuardZonesEqual(zBufBefore, zBuf, OffZ, size, label + " Multiply zBuf");
            }

            // --- Square ---
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] zRef = BinPolys.Create(poly.Size);
                poly.Square(x, 0, zRef, 0);

                ulong[] xBuf = PadBuffer(size, OffX, OffPadTail, random);
                ulong[] zBuf = PadBuffer(size, OffZ, OffPadTail, random);
                Array.Copy(x, 0, xBuf, OffX, size);
                ulong[] xBufBefore = (ulong[])xBuf.Clone();
                ulong[] zBufBefore = (ulong[])zBuf.Clone();

                poly.Square(xBuf, OffX, zBuf, OffZ);

                AssertSliceEquals(zRef, zBuf, OffZ, size, label + " Square");
                Assert.AreEqual(xBufBefore, xBuf, label + " Square xBuf clobbered");
                AssertGuardZonesEqual(zBufBefore, zBuf, OffZ, size, label + " Square zBuf");
            }

            // --- SquareN (sn > 1 exercises the inner loop's Expand64To128(z, zOff, ...) read).
            {
                const int sn = 7;
                ulong[] x = RandomReduced(random, n);
                ulong[] zRef = BinPolys.Create(poly.Size);
                poly.SquareN(x, 0, sn, zRef, 0);

                ulong[] xBuf = PadBuffer(size, OffX, OffPadTail, random);
                ulong[] zBuf = PadBuffer(size, OffZ, OffPadTail, random);
                Array.Copy(x, 0, xBuf, OffX, size);
                ulong[] xBufBefore = (ulong[])xBuf.Clone();
                ulong[] zBufBefore = (ulong[])zBuf.Clone();

                poly.SquareN(xBuf, OffX, sn, zBuf, OffZ);

                AssertSliceEquals(zRef, zBuf, OffZ, size, label + " SquareN");
                Assert.AreEqual(xBufBefore, xBuf, label + " SquareN xBuf clobbered");
                AssertGuardZonesEqual(zBufBefore, zBuf, OffZ, size, label + " SquareN zBuf");
            }

            // --- Add ---
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] y = RandomReduced(random, n);
                ulong[] zRef = BinPolys.Create(poly.Size);
                BinPolys.Add(size, x, 0, y, 0, zRef, 0);

                ulong[] xBuf = PadBuffer(size, OffX, OffPadTail, random);
                ulong[] yBuf = PadBuffer(size, OffY, OffPadTail, random);
                ulong[] zBuf = PadBuffer(size, OffZ, OffPadTail, random);
                Array.Copy(x, 0, xBuf, OffX, size);
                Array.Copy(y, 0, yBuf, OffY, size);
                ulong[] xBufBefore = (ulong[])xBuf.Clone();
                ulong[] yBufBefore = (ulong[])yBuf.Clone();
                ulong[] zBufBefore = (ulong[])zBuf.Clone();

                BinPolys.Add(size, xBuf, OffX, yBuf, OffY, zBuf, OffZ);

                AssertSliceEquals(zRef, zBuf, OffZ, size, label + " Add");
                Assert.AreEqual(xBufBefore, xBuf, label + " Add xBuf clobbered");
                Assert.AreEqual(yBufBefore, yBuf, label + " Add yBuf clobbered");
                AssertGuardZonesEqual(zBufBefore, zBuf, OffZ, size, label + " Add zBuf");
            }

            // --- AddTo (z is both read and written; pick a non-zero starting z) ---
            {
                ulong[] x = RandomReduced(random, n);
                ulong[] zInit = RandomReduced(random, n);
                ulong[] zRef = (ulong[])zInit.Clone();
                BinPolys.AddTo(size, x, 0, zRef, 0);

                ulong[] xBuf = PadBuffer(size, OffX, OffPadTail, random);
                ulong[] zBuf = PadBuffer(size, OffZ, OffPadTail, random);
                Array.Copy(x, 0, xBuf, OffX, size);
                Array.Copy(zInit, 0, zBuf, OffZ, size);
                ulong[] xBufBefore = (ulong[])xBuf.Clone();
                ulong[] zBufBefore = (ulong[])zBuf.Clone();

                BinPolys.AddTo(size, xBuf, OffX, zBuf, OffZ);

                AssertSliceEquals(zRef, zBuf, OffZ, size, label + " AddTo");
                Assert.AreEqual(xBufBefore, xBuf, label + " AddTo xBuf clobbered");
                AssertGuardZonesEqual(zBufBefore, zBuf, OffZ, size, label + " AddTo zBuf");
            }
        }

        /// <summary>
        /// Allocate <c>sliceOff + sliceSize + padTail</c> limbs and fill every limb with random
        /// bytes — the head and tail regions become guard zones for off-by-one detection, and
        /// the caller will overwrite the active <c>[sliceOff..sliceOff+sliceSize)</c> slice
        /// with its real payload before the op runs.
        /// </summary>
        private static ulong[] PadBuffer(int sliceSize, int sliceOff, int padTail, Random random)
        {
            int total = sliceOff + sliceSize + padTail;
            ulong[] buf = new ulong[total];
            byte[] bytes = new byte[total << 3];
            random.NextBytes(bytes);
            for (int i = 0; i < total; ++i)
            {
                ulong w = 0UL;
                for (int j = 0; j < 8; ++j)
                {
                    w |= (ulong)bytes[(i << 3) + j] << (j << 3);
                }
                buf[i] = w;
            }
            return buf;
        }

        private static void AssertSliceEquals(ulong[] expected, ulong[] actual, int actualOff,
            int size, string context)
        {
            for (int i = 0; i < size; ++i)
            {
                Assert.AreEqual(expected[i], actual[actualOff + i], context + " limb " + i);
            }
        }

        private static void AssertGuardZonesEqual(ulong[] before, ulong[] after, int sliceOff,
            int sliceSize, string context)
        {
            for (int i = 0; i < sliceOff; ++i)
            {
                Assert.AreEqual(before[i], after[i], context + " head guard at " + i);
            }
            for (int i = sliceOff + sliceSize; i < after.Length; ++i)
            {
                Assert.AreEqual(before[i], after[i], context + " tail guard at " + i);
            }
        }

        // ----- Benchmarks (run with --filter Bench_) -----

        [Test, Explicit]
        [TestCaseSource(nameof(BikeBinomials))]
        public void Bench_Binomial_Square(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);
            Array.Copy(x, z, x.Length);

            // Warm-up.
            for (int i = 0; i < 100; ++i)
            {
                binomial.Square(z, 0, z, 0);
            }

            const int iters = 50_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                binomial.Square(z, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Square: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(BikeBinomials))]
        public void Bench_Binomial_Multiply(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);

            // Warm-up.
            for (int i = 0; i < 100; ++i)
            {
                binomial.Multiply(x, 0, y, 0, z, 0);
            }

            const int iters = 5_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                binomial.Multiply(x, 0, y, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Multiply: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(SmallBinomials))]
        public void Bench_SmallBinomial_Multiply(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);

            // Warm-up.
            for (int i = 0; i < 1000; ++i)
            {
                binomial.Multiply(x, 0, y, 0, z, 0);
            }

            const int iters = 10_000_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                binomial.Multiply(x, 0, y, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Multiply: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(MediumBinomials))]
        public void Bench_MediumBinomial_Multiply(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);

            // Warm-up.
            for (int i = 0; i < 1000; ++i)
            {
                binomial.Multiply(x, 0, y, 0, z, 0);
            }

            const int iters = 1_000_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                binomial.Multiply(x, 0, y, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Multiply: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        public void Bench_Trinomial_Square(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            Array.Copy(x, z, x.Length);

            // Warm-up.
            for (int i = 0; i < 1000; ++i)
            {
                trinomial.Square(z, 0, z, 0);
            }

            const int iters = 5_000_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                trinomial.Square(z, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Square: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(SectTrinomials))]
        [TestCaseSource(nameof(SyntheticTrinomialsA))]
        public void Bench_Trinomial_Multiply(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);

            // Warm-up.
            for (int i = 0; i < 1000; ++i)
            {
                trinomial.Multiply(x, 0, y, 0, z, 0);
            }

            const int iters = 5_000_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                trinomial.Multiply(x, 0, y, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Multiply: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(SectPentanomials))]
        public void Bench_Pentanomial_Square(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            Array.Copy(x, z, x.Length);

            // Warm-up.
            for (int i = 0; i < 1000; ++i)
            {
                pentanomial.Square(z, 0, z, 0);
            }

            const int iters = 5_000_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                pentanomial.Square(z, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Square: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        [Test, Explicit]
        [TestCaseSource(nameof(SectPentanomials))]
        public void Bench_Pentanomial_Multiply(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);

            // Warm-up.
            for (int i = 0; i < 1000; ++i)
            {
                pentanomial.Multiply(x, 0, y, 0, z, 0);
            }

            const int iters = 5_000_000;
            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; ++i)
            {
                pentanomial.Multiply(x, 0, y, 0, z, 0);
            }
            sw.Stop();

            double usPerOp = sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
            TestContext.WriteLine(
                $"{label} Multiply: {iters:N0} ops in {sw.ElapsedMilliseconds:N0} ms ({usPerOp:N3} us/op)");
        }

        // ----- Performance-curve benchmarks (run with --filter Bench_PerfGraph_) -----
        //
        // Goal: emit machine-readable CSV rows (line prefix "BINPOLY_CSV,") describing the
        // multiply / square runtime curves of each non-bitwise reducer family as a
        // function of n. Bitwise families (TrinomialReduce.D, PentanomialReduce.C) are
        // omitted: slow, never reached by shipped consumers, and not of interest.
        //
        // Per-family coverage of n in [65, 640]: all standardised SECT named curves that
        // route to the family, plus one synthetic case (smallest valid odd n) in every
        // (n / 32) bucket in [2, 19] not already covered by a SECT curve. Binomial instead
        // enumerates the BIKE and HQC ring sizes (no synthetic fills).
        //
        // CSV output (one row per case, via TestContext.WriteLine):
        //   BINPOLY_CSV,<poly_type>,<family>,<op>,<label>,<n>,<us_per_op>
        // To extract: dotnet test --filter Bench_PerfGraph_ ... | findstr "BINPOLY_CSV,"
        //
        // Timing: 1000-iter warmup, then 3 time-budgeted passes (each runs the op until
        // ~PerfGraphPassBudgetMs elapsed), reported as median-of-3. The Action wrapper
        // adds a small constant per-op overhead (~5 ns on the dev machine), so absolute
        // numbers slightly overstate vs the inline Bench_* benches above; relative
        // curves are unaffected.

        private const double PerfGraphPassBudgetMs = 500.0;
        private const int PerfGraphBatchSize = 64;

        // Binomial perf-graph cases: BIKE and HQC ring sizes, ordered by n.
        private static readonly object[] PerfGraphBinomials =
        {
            new object[] { "bike1",  BikeR1 },
            new object[] { "hqc128", HqcR128 },
            new object[] { "bike3",  BikeR3 },
            new object[] { "hqc192", HqcR192 },
            new object[] { "bike5",  BikeR5 },
            new object[] { "hqc256", HqcR256 },
        };

        // Trinomial-A perf-graph cases: SECT curves routing to A, plus synthetic fills
        // for empty (n / 32) buckets in [2, 19]. Synthetic n = 32 * b + 1 (smallest
        // valid odd n in bucket b), k = 1.
        private static readonly object[] PerfGraphTrinomialA =
        {
            new object[] { "synA_n65",   65,  1 },   // bucket 2
            new object[] { "sect113",   113,  9 },   // bucket 3
            new object[] { "synA_n129", 129,  1 },   // bucket 4
            new object[] { "synA_n161", 161,  1 },   // bucket 5
            new object[] { "sect193",   193, 15 },   // bucket 6
            new object[] { "synA_n225", 225,  1 },   // bucket 7
            new object[] { "synA_n257", 257,  1 },   // bucket 8
            new object[] { "synA_n289", 289,  1 },   // bucket 9
            new object[] { "synA_n321", 321,  1 },   // bucket 10
            new object[] { "synA_n353", 353,  1 },   // bucket 11
            new object[] { "synA_n385", 385,  1 },   // bucket 12
            new object[] { "synA_n417", 417,  1 },   // bucket 13
            new object[] { "synA_n449", 449,  1 },   // bucket 14
            new object[] { "synA_n481", 481,  1 },   // bucket 15
            new object[] { "synA_n513", 513,  1 },   // bucket 16
            new object[] { "synA_n545", 545,  1 },   // bucket 17
            new object[] { "synA_n577", 577,  1 },   // bucket 18
            new object[] { "synA_n609", 609,  1 },   // bucket 19
        };

        // Trinomial-B perf-graph cases: no SECT curve routes to B; all synthetic.
        // Smallest valid bucket is 4 (B needs k a multiple of 64, k >= 64, n - k >= 64
        // so n >= 129). Synthetic n = 32 * b + 1, k = 64.
        private static readonly object[] PerfGraphTrinomialB =
        {
            new object[] { "synB_n129", 129, 64 },   // bucket 4
            new object[] { "synB_n161", 161, 64 },   // bucket 5
            new object[] { "synB_n193", 193, 64 },   // bucket 6
            new object[] { "synB_n225", 225, 64 },   // bucket 7
            new object[] { "synB_n257", 257, 64 },   // bucket 8
            new object[] { "synB_n289", 289, 64 },   // bucket 9
            new object[] { "synB_n321", 321, 64 },   // bucket 10
            new object[] { "synB_n353", 353, 64 },   // bucket 11
            new object[] { "synB_n385", 385, 64 },   // bucket 12
            new object[] { "synB_n417", 417, 64 },   // bucket 13
            new object[] { "synB_n449", 449, 64 },   // bucket 14
            new object[] { "synB_n481", 481, 64 },   // bucket 15
            new object[] { "synB_n513", 513, 64 },   // bucket 16
            new object[] { "synB_n545", 545, 64 },   // bucket 17
            new object[] { "synB_n577", 577, 64 },   // bucket 18
            new object[] { "synB_n609", 609, 64 },   // bucket 19
        };

        // Trinomial-C perf-graph cases: SECT curves routing to C, plus synthetic fills
        // for empty buckets in [4, 19]. C needs k >= 64 with (k & 63) != 0, n - k >= 64.
        // Synthetic n = 32 * b + 1, k = 65 (smallest valid).
        private static readonly object[] PerfGraphTrinomialC =
        {
            new object[] { "synC_n129", 129,  65 },   // bucket 4
            new object[] { "synC_n161", 161,  65 },   // bucket 5
            new object[] { "synC_n193", 193,  65 },   // bucket 6
            new object[] { "sect233",   233,  74 },   // bucket 7
            new object[] { "sect239",   239, 158 },   // bucket 7 (same bucket)
            new object[] { "synC_n257", 257,  65 },   // bucket 8
            new object[] { "synC_n289", 289,  65 },   // bucket 9
            new object[] { "synC_n321", 321,  65 },   // bucket 10
            new object[] { "synC_n353", 353,  65 },   // bucket 11
            new object[] { "sect409",   409,  87 },   // bucket 12
            new object[] { "synC_n417", 417,  65 },   // bucket 13
            new object[] { "synC_n449", 449,  65 },   // bucket 14
            new object[] { "synC_n481", 481,  65 },   // bucket 15
            new object[] { "synC_n513", 513,  65 },   // bucket 16
            new object[] { "synC_n545", 545,  65 },   // bucket 17
            new object[] { "synC_n577", 577,  65 },   // bucket 18
            new object[] { "synC_n609", 609,  65 },   // bucket 19
        };

        // Pentanomial-A perf-graph cases: SECT curves routing to A, plus synthetic fills
        // for empty buckets in [2, 19]. Bucket 2 needs n = 67 (n = 65 fails A's
        // n - k3 >= 64 with k1 < k2 < k3 forcing k3 >= 3); other buckets use n = 32 * b + 1.
        // k_i = (1, 2, 3) (smallest valid all-k_i-< 64 triple).
        private static readonly object[] PerfGraphPentanomialA =
        {
            new object[] { "synPA_n67",   67, 1, 2,  3 },   // bucket 2
            new object[] { "synPA_n97",   97, 1, 2,  3 },   // bucket 3
            new object[] { "sect131",    131, 2, 3,  8 },   // bucket 4
            new object[] { "sect163",    163, 3, 6,  7 },   // bucket 5
            new object[] { "synPA_n193", 193, 1, 2,  3 },   // bucket 6
            new object[] { "synPA_n225", 225, 1, 2,  3 },   // bucket 7
            new object[] { "sect283",    283, 5, 7, 12 },   // bucket 8
            new object[] { "synPA_n289", 289, 1, 2,  3 },   // bucket 9
            new object[] { "synPA_n321", 321, 1, 2,  3 },   // bucket 10
            new object[] { "synPA_n353", 353, 1, 2,  3 },   // bucket 11
            new object[] { "synPA_n385", 385, 1, 2,  3 },   // bucket 12
            new object[] { "synPA_n417", 417, 1, 2,  3 },   // bucket 13
            new object[] { "synPA_n449", 449, 1, 2,  3 },   // bucket 14
            new object[] { "synPA_n481", 481, 1, 2,  3 },   // bucket 15
            new object[] { "synPA_n513", 513, 1, 2,  3 },   // bucket 16
            new object[] { "sect571",    571, 2, 5, 10 },   // bucket 17
            new object[] { "synPA_n577", 577, 1, 2,  3 },   // bucket 18
            new object[] { "synPA_n609", 609, 1, 2,  3 },   // bucket 19
        };

        // Pentanomial-B perf-graph cases: no SECT curve routes to B; all synthetic.
        // B requires k2 >= 64 and (k_i & 63) != 0 for all k_i. Smallest valid n is 131
        // (n = 129 would force k3 = 65 and then k2 < k3 with k2 >= 65 is unreachable).
        // k = (1, 65, 67) constant across cases.
        private static readonly object[] PerfGraphPentanomialB =
        {
            new object[] { "synPB_n131", 131, 1, 65, 67 },   // bucket 4
            new object[] { "synPB_n161", 161, 1, 65, 67 },   // bucket 5
            new object[] { "synPB_n193", 193, 1, 65, 67 },   // bucket 6
            new object[] { "synPB_n225", 225, 1, 65, 67 },   // bucket 7
            new object[] { "synPB_n257", 257, 1, 65, 67 },   // bucket 8
            new object[] { "synPB_n289", 289, 1, 65, 67 },   // bucket 9
            new object[] { "synPB_n321", 321, 1, 65, 67 },   // bucket 10
            new object[] { "synPB_n353", 353, 1, 65, 67 },   // bucket 11
            new object[] { "synPB_n385", 385, 1, 65, 67 },   // bucket 12
            new object[] { "synPB_n417", 417, 1, 65, 67 },   // bucket 13
            new object[] { "synPB_n449", 449, 1, 65, 67 },   // bucket 14
            new object[] { "synPB_n481", 481, 1, 65, 67 },   // bucket 15
            new object[] { "synPB_n513", 513, 1, 65, 67 },   // bucket 16
            new object[] { "synPB_n545", 545, 1, 65, 67 },   // bucket 17
            new object[] { "synPB_n577", 577, 1, 65, 67 },   // bucket 18
            new object[] { "synPB_n609", 609, 1, 65, 67 },   // bucket 19
        };

        // Pentanomial-D perf-graph cases: no SECT curve routes to D; all synthetic.
        // D requires k1, k2 < 64 and k3 >= 64 with (k3 & 63) != 0 and n - k3 >= 64.
        // k = (1, 2, 65) routes to D; smallest valid bucket is 4 (n = 129, n - k3 = 64).
        private static readonly object[] PerfGraphPentanomialD =
        {
            new object[] { "synPD_n129", 129, 1, 2, 65 },   // bucket 4
            new object[] { "synPD_n161", 161, 1, 2, 65 },   // bucket 5
            new object[] { "synPD_n193", 193, 1, 2, 65 },   // bucket 6
            new object[] { "synPD_n225", 225, 1, 2, 65 },   // bucket 7
            new object[] { "synPD_n257", 257, 1, 2, 65 },   // bucket 8
            new object[] { "synPD_n289", 289, 1, 2, 65 },   // bucket 9
            new object[] { "synPD_n321", 321, 1, 2, 65 },   // bucket 10
            new object[] { "synPD_n353", 353, 1, 2, 65 },   // bucket 11
            new object[] { "synPD_n385", 385, 1, 2, 65 },   // bucket 12
            new object[] { "synPD_n417", 417, 1, 2, 65 },   // bucket 13
            new object[] { "synPD_n449", 449, 1, 2, 65 },   // bucket 14
            new object[] { "synPD_n481", 481, 1, 2, 65 },   // bucket 15
            new object[] { "synPD_n513", 513, 1, 2, 65 },   // bucket 16
            new object[] { "synPD_n545", 545, 1, 2, 65 },   // bucket 17
            new object[] { "synPD_n577", 577, 1, 2, 65 },   // bucket 18
            new object[] { "synPD_n609", 609, 1, 2, 65 },   // bucket 19
        };

        // ----- Timing helpers -----

        private static double BenchMedian3(Action op)
        {
            // Warmup pass (its result is discarded).
            for (int i = 0; i < 1000; ++i)
            {
                op();
            }
            double a = TimedPass(op);
            double b = TimedPass(op);
            double c = TimedPass(op);
            return Median3(a, b, c);
        }

        private static double TimedPass(Action op)
        {
            long iters = 0;
            var sw = Stopwatch.StartNew();
            while (sw.Elapsed.TotalMilliseconds < PerfGraphPassBudgetMs)
            {
                for (int j = 0; j < PerfGraphBatchSize; ++j)
                {
                    op();
                }
                iters += PerfGraphBatchSize;
            }
            sw.Stop();
            return sw.Elapsed.TotalMilliseconds * 1000.0 / iters;
        }

        private static double Median3(double a, double b, double c)
        {
            double max = System.Math.Max(a, System.Math.Max(b, c));
            double min = System.Math.Min(a, System.Math.Min(b, c));
            return a + b + c - max - min;
        }

        private static void EmitPerfGraphCsv(string polyType, string family, string op, string label,
            int n, double usPerOp)
        {
            TestContext.WriteLine($"BINPOLY_CSV,{polyType},{family},{op},{label},{n},{usPerOp:F4}");
        }

        // ----- Binomial perf-graph benches -----

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphBinomials))]
        public void Bench_PerfGraph_Binomial_Multiply(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);
            double us = BenchMedian3(() => binomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("binomial", "Binomial", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphBinomials))]
        public void Bench_PerfGraph_Binomial_Square(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => binomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("binomial", "Binomial", "Sqr", label, n, us);
        }

        // ----- Medium-band binomial perf-graph benches -----
        //
        // Covers size in [11, 32) with the same median-of-3 noise discipline
        // as the BIKE / HQC PerfGraph benches above. Distinct from Bench_MediumBinomial_*
        // (fixed 1,000,000-iter timing) — the PerfGraph variant uses BenchMedian3 so
        // small-effect changes have a low noise floor at small per-op cost.

        [Test, Explicit]
        [TestCaseSource(nameof(MediumBinomials))]
        public void Bench_PerfGraph_MediumBinomial_Multiply(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);
            double us = BenchMedian3(() => binomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("binomial", "Medium", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(MediumBinomials))]
        public void Bench_PerfGraph_MediumBinomial_Square(string label, int n)
        {
            var binomial = BinPolys.Mul.Binomial(n);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(binomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => binomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("binomial", "Medium", "Sqr", label, n, us);
        }

        // ----- Trinomial perf-graph benches -----

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphTrinomialA))]
        public void Bench_PerfGraph_TrinomialA_Multiply(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            double us = BenchMedian3(() => trinomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("trinomial", "A", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphTrinomialA))]
        public void Bench_PerfGraph_TrinomialA_Square(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => trinomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("trinomial", "A", "Sqr", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphTrinomialB))]
        public void Bench_PerfGraph_TrinomialB_Multiply(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            double us = BenchMedian3(() => trinomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("trinomial", "B", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphTrinomialB))]
        public void Bench_PerfGraph_TrinomialB_Square(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => trinomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("trinomial", "B", "Sqr", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphTrinomialC))]
        public void Bench_PerfGraph_TrinomialC_Multiply(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            double us = BenchMedian3(() => trinomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("trinomial", "C", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphTrinomialC))]
        public void Bench_PerfGraph_TrinomialC_Square(string label, int n, int k)
        {
            var trinomial = BinPolys.Mul.Trinomial(n, k);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(trinomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => trinomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("trinomial", "C", "Sqr", label, n, us);
        }

        // ----- Pentanomial perf-graph benches -----

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphPentanomialA))]
        public void Bench_PerfGraph_PentanomialA_Multiply(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            double us = BenchMedian3(() => pentanomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("pentanomial", "A", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphPentanomialA))]
        public void Bench_PerfGraph_PentanomialA_Square(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => pentanomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("pentanomial", "A", "Sqr", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphPentanomialB))]
        public void Bench_PerfGraph_PentanomialB_Multiply(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            double us = BenchMedian3(() => pentanomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("pentanomial", "B", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphPentanomialB))]
        public void Bench_PerfGraph_PentanomialB_Square(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => pentanomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("pentanomial", "B", "Sqr", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphPentanomialD))]
        public void Bench_PerfGraph_PentanomialD_Multiply(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] y = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            double us = BenchMedian3(() => pentanomial.Multiply(x, 0, y, 0, z, 0));
            EmitPerfGraphCsv("pentanomial", "D", "Mul", label, n, us);
        }

        [Test, Explicit]
        [TestCaseSource(nameof(PerfGraphPentanomialD))]
        public void Bench_PerfGraph_PentanomialD_Square(string label, int n, int k1, int k2, int k3)
        {
            var pentanomial = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var rng = new Random(FixedSeed + n);
            ulong[] x = RandomReduced(rng, n);
            ulong[] z = BinPolys.Create(pentanomial.Size);
            Array.Copy(x, z, x.Length);
            double us = BenchMedian3(() => pentanomial.Square(z, 0, z, 0));
            EmitPerfGraphCsv("pentanomial", "D", "Sqr", label, n, us);
        }

        [Test]
        public void Factory_RejectsInvalidParameters()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => BinPolys.Mul.Binomial(0));
            Assert.Throws<ArgumentOutOfRangeException>(() => BinPolys.Mul.Binomial(-1));

            Assert.Throws<ArgumentOutOfRangeException>(() => BinPolys.Mul.Trinomial(BikeR1, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => BinPolys.Mul.Trinomial(BikeR1, BikeR1));
            Assert.Throws<ArgumentOutOfRangeException>(() => BinPolys.Mul.Trinomial(2, 1));   // n < 3

            Assert.Throws<ArgumentException>(() => BinPolys.Mul.Pentanomial(BikeR1, 5, 5, 9));      // k2 not > k1
            Assert.Throws<ArgumentException>(() => BinPolys.Mul.Pentanomial(BikeR1, 1, 5, 5));      // k3 not > k2
            Assert.Throws<ArgumentException>(() => BinPolys.Mul.Pentanomial(BikeR1, 1, 3, BikeR1)); // k3 not < n
            Assert.Throws<ArgumentOutOfRangeException>(() => BinPolys.Mul.Pentanomial(4, 1, 2, 3)); // n < 5
        }

        [Test]
        public void Factory_AcceptsEvenN()
        {
            // The odd-n restriction was lifted; even n (including multiples of 64, which route to
            // the word-aligned / bitwise reducers) is now accepted.
            Assert.DoesNotThrow(() => BinPolys.Mul.Binomial(2));
            Assert.DoesNotThrow(() => BinPolys.Mul.Binomial(64));
            Assert.DoesNotThrow(() => BinPolys.Mul.Trinomial(4, 1));
            Assert.DoesNotThrow(() => BinPolys.Mul.Trinomial(64, 1));
            Assert.DoesNotThrow(() => BinPolys.Mul.Trinomial(128, 7));
            Assert.DoesNotThrow(() => BinPolys.Mul.Pentanomial(6, 1, 2, 3));
            Assert.DoesNotThrow(() => BinPolys.Mul.Pentanomial(64, 1, 2, 3));
            Assert.DoesNotThrow(() => BinPolys.Mul.Pentanomial(128, 2, 5, 7));
        }

        // ----- Inversion (Itoh-Tsujii) -----
        //
        // Inversion is only valid over a field, i.e. an irreducible reduction polynomial. The SECT
        // trinomials / pentanomials and the X9.62 c2pnb* pentanomials (even m) are irreducible; the
        // synthetic (n, k) data sources are NOT, and the binomial x^n + 1 is never a field, so none
        // of those are exercised here.

        [TestCaseSource(nameof(SectTrinomials))]
        public void Trinomial_Invert_RoundTrip(string label, int n, int k)
        {
            var mul = BinPolys.Mul.Trinomial(n, k);
            var inv = BinPolys.Inv.ItohTsujii(mul);
            RunInvertChecks(mul, inv, n, new Random(FixedSeed + 1400 + n), label);
        }

        [TestCaseSource(nameof(SectPentanomials))]
        [TestCaseSource(nameof(X962EvenPentanomials))]
        public void Pentanomial_Invert_RoundTrip(string label, int n, int k1, int k2, int k3)
        {
            var mul = BinPolys.Mul.Pentanomial(n, k1, k2, k3);
            var inv = BinPolys.Inv.ItohTsujii(mul);
            RunInvertChecks(mul, inv, n, new Random(FixedSeed + 1500 + n), label);
        }

        [Test]
        public void Inv_Factory_RejectsNullAndDegenerate()
        {
            Assert.Throws<ArgumentNullException>(() => BinPolys.Inv.ItohTsujii(null));
            // n = 1 (degenerate GF(2)) is below field degree; only the binomial factory can yield it.
            Assert.Throws<ArgumentException>(() => BinPolys.Inv.ItohTsujii(BinPolys.Mul.Binomial(1)));
        }

        // Round-trip + involution + 0/1 fixed points + in-place, for an irreducible (field) modulus.
        private static void RunInvertChecks(IBinPolyMul mul, IBinPolyInv inv, int n, Random random,
            string label)
        {
            int size = mul.Size;

            ulong[] one = BinPolys.Create(size);
            one[0] = 1UL;
            ulong[] zero = BinPolys.Create(size);

            // No special case: 0 -> 0 and 1 -> 1 fall out of the chain.
            ulong[] zInv = BinPolys.Create(size);
            inv.Invert(zero, 0, zInv, 0);
            Assert.AreEqual(zero, zInv, label + " Invert(0)");
            inv.Invert(one, 0, zInv, 0);
            Assert.AreEqual(one, zInv, label + " Invert(1)");

            for (int t = 0; t < RandomTrials; ++t)
            {
                ulong[] a = RandomReduced(random, n);
                if (BinPolys.EqualTo(size, a, 0, zero, 0) != 0)
                    continue;   // skip the (astronomically unlikely) all-zero draw

                ulong[] aInv = BinPolys.Create(size);
                inv.Invert(a, 0, aInv, 0);

                // a * a^{-1} == 1  -- THE correctness check in a field.
                ulong[] prod = BinPolys.Create(size);
                mul.Multiply(a, 0, aInv, 0, prod, 0);
                Assert.AreEqual(one, prod, label + " a * inv(a) trial " + t);

                // Involution: inv(inv(a)) == a.
                ulong[] aInvInv = BinPolys.Create(size);
                inv.Invert(aInv, 0, aInvInv, 0);
                Assert.AreEqual(a, aInvInv, label + " inv(inv(a)) trial " + t);
            }

            // In-place: x aliases z.
            ulong[] b = RandomReduced(random, n);
            if (BinPolys.EqualTo(size, b, 0, zero, 0) == 0)
            {
                ulong[] expected = BinPolys.Create(size);
                inv.Invert(b, 0, expected, 0);
                inv.Invert(b, 0, b, 0);   // in-place
                Assert.AreEqual(expected, b, label + " in-place invert");
            }
        }

        // ----- BitLengthVar -----

        [Test]
        public void BitLengthVar_AgainstReference()
        {
            var random = new Random(FixedSeed + 1600);

            foreach (int size in new[] { 1, 2, 3, 5, 9 })
            {
                ulong[] zero = new ulong[size];
                Assert.AreEqual(0, BinPolys.BitLengthVar(size, zero, 0), "zero size " + size);

                ulong[] one = new ulong[size];
                one[0] = 1UL;
                Assert.AreEqual(1, BinPolys.BitLengthVar(size, one, 0), "one size " + size);

                ulong[] top = new ulong[size];
                top[size - 1] = 1UL << 63;
                Assert.AreEqual(size * 64, BinPolys.BitLengthVar(size, top, 0), "top size " + size);

                for (int t = 0; t < 32; ++t)
                {
                    ulong[] x = RandomLimbs(random, size);
                    Assert.AreEqual(ReferenceBitLength(size, x), BinPolys.BitLengthVar(size, x, 0),
                        "size " + size + " trial " + t);
                }
            }
        }

        private static ulong[] RandomLimbs(Random random, int size)
        {
            ulong[] x = new ulong[size];
            byte[] buf = new byte[size << 3];
            random.NextBytes(buf);
            for (int i = 0; i < size; ++i)
            {
                ulong w = 0UL;
                for (int j = 0; j < 8; ++j)
                {
                    w |= (ulong)buf[(i << 3) + j] << (j << 3);
                }
                x[i] = w;
            }
            return x;
        }

        // Obviously-correct reference: scan bits from the top down, return (MSB index + 1), 0 if none.
        private static int ReferenceBitLength(int size, ulong[] x)
        {
            for (int bit = (size << 6) - 1; bit >= 0; --bit)
            {
                if (((x[bit >> 6] >> (bit & 63)) & 1UL) != 0UL)
                    return bit + 1;
            }
            return 0;
        }

        // ----- Reference implementation -----

        /// <summary>
        /// Reference carryless extended product of two degree-&lt;<paramref name="n"/> polynomials.
        /// Computes <c>x * y</c> in <c>GF(2)[X]</c> via a shift-and-XOR schoolbook (outer loop over
        /// set bits of <paramref name="x"/>). Returns a <c>2 * size</c>-limb buffer holding the
        /// unreduced product. Slow but obviously correct; used as the building block for the
        /// reference reducers.
        /// </summary>
        private static ulong[] CarrylessMul(int n, ulong[] x, ulong[] y)
        {
            int size = (n + 63) >> 6;
            ulong[] zz = new ulong[2 * size];

            for (int i = 0; i < n; ++i)
            {
                if (((x[i >> 6] >> (i & 63)) & 1UL) == 0UL)
                    continue;

                int wOff = i >> 6;
                int bOff = i & 63;
                if (bOff == 0)
                {
                    for (int j = 0; j < size; ++j)
                    {
                        zz[wOff + j] ^= y[j];
                    }
                }
                else
                {
                    for (int j = 0; j < size; ++j)
                    {
                        ulong yj = y[j];
                        zz[wOff + j] ^= yj << bOff;
                        zz[wOff + j + 1] ^= yj >> (64 - bOff);
                    }
                }
            }

            return zz;
        }

        /// <summary>
        /// Reference carryless multiply modulo <c>x^r + 1</c>. Folds each bit at positions
        /// <c>[r, 2r-1]</c> back to position <c>p - r</c>.
        /// </summary>
        private static ulong[] ReferenceBinomialMul(int r, ulong[] x, ulong[] y)
        {
            int size = (r + 63) >> 6;
            ulong[] zz = CarrylessMul(r, x, y);

            ulong[] z = new ulong[size];
            Array.Copy(zz, 0, z, 0, size);

            // Fold bits at positions [r, 2r-1] into positions [0, r-1].
            for (int p = r; p < 2 * r - 1; ++p)
            {
                if (((zz[p >> 6] >> (p & 63)) & 1UL) == 0UL)
                    continue;

                int q = p - r;
                z[q >> 6] ^= 1UL << (q & 63);
            }

            int partial = r & 63;
            ulong partialMask = partial == 0 ? ulong.MaxValue : (1UL << partial) - 1UL;
            z[size - 1] &= partialMask;
            return z;
        }

        /// <summary>
        /// Reference carryless multiply modulo <c>x^n + x^k + 1</c>. Folds each bit at positions
        /// <c>[n, 2n-2]</c> top-down via the +1 tap (lands at <c>p - n</c>) and the +x^k tap (lands
        /// at <c>p - n + k</c>). The top-down order means contributions of the +x^k tap that land
        /// above <c>n</c> are picked up by later iterations. Residual bits left set at positions
        /// <c>&gt;= n</c> are ignored when the result is truncated and masked.
        /// </summary>
        private static ulong[] ReferenceTrinomialMul(int n, int k, ulong[] x, ulong[] y)
        {
            int size = (n + 63) >> 6;
            ulong[] zz = CarrylessMul(n, x, y);

            for (int p = 2 * n - 2; p >= n; --p)
            {
                if (((zz[p >> 6] >> (p & 63)) & 1UL) == 0UL)
                    continue;

                int q0 = p - n;
                int q1 = p - n + k;
                zz[q0 >> 6] ^= 1UL << (q0 & 63);
                zz[q1 >> 6] ^= 1UL << (q1 & 63);
            }

            ulong[] z = new ulong[size];
            Array.Copy(zz, 0, z, 0, size);

            int partial = n & 63;
            ulong partialMask = partial == 0 ? ulong.MaxValue : (1UL << partial) - 1UL;
            z[size - 1] &= partialMask;
            return z;
        }

        /// <summary>
        /// Reference carryless multiply modulo <c>x^n + x^k3 + x^k2 + x^k1 + 1</c> with
        /// <c>0 &lt; k1 &lt; k2 &lt; k3 &lt; n</c>. Folds each bit at positions <c>[n, 2n-2]</c>
        /// top-down via the four taps; new contributions above <c>n</c> are picked up by later
        /// iterations. Residual bits left set at positions <c>&gt;= n</c> are ignored when the
        /// result is truncated and masked.
        /// </summary>
        private static ulong[] ReferencePentanomialMul(int n, int k1, int k2, int k3, ulong[] x,
            ulong[] y)
        {
            int size = (n + 63) >> 6;
            ulong[] zz = CarrylessMul(n, x, y);

            for (int p = 2 * n - 2; p >= n; --p)
            {
                if (((zz[p >> 6] >> (p & 63)) & 1UL) == 0UL)
                    continue;

                int q0 = p - n;
                int q1 = p - n + k1;
                int q2 = p - n + k2;
                int q3 = p - n + k3;
                zz[q0 >> 6] ^= 1UL << (q0 & 63);
                zz[q1 >> 6] ^= 1UL << (q1 & 63);
                zz[q2 >> 6] ^= 1UL << (q2 & 63);
                zz[q3 >> 6] ^= 1UL << (q3 & 63);
            }

            ulong[] z = new ulong[size];
            Array.Copy(zz, 0, z, 0, size);

            int partial = n & 63;
            ulong partialMask = partial == 0 ? ulong.MaxValue : (1UL << partial) - 1UL;
            z[size - 1] &= partialMask;
            return z;
        }

        /// <summary>
        /// Generate a uniformly random polynomial of degree at most <c>n - 1</c>, packed into the
        /// <c>(n + 63) / 64</c> low limbs with the high limb masked to ensure no bits at positions
        /// <c>>= n</c>.
        /// </summary>
        private static ulong[] RandomReduced(Random random, int n)
        {
            int size = (n + 63) >> 6;
            ulong[] z = new ulong[size];
            byte[] buf = new byte[size << 3];
            random.NextBytes(buf);
            for (int i = 0; i < size; ++i)
            {
                ulong w = 0UL;
                for (int j = 0; j < 8; ++j)
                {
                    w |= (ulong)buf[(i << 3) + j] << (j << 3);
                }
                z[i] = w;
            }
            int partial = n & 63;
            if (partial != 0)
            {
                z[size - 1] &= (1UL << partial) - 1UL;
            }
            return z;
        }
    }
}
#endif
