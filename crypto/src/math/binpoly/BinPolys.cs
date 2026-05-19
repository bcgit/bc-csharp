using System;

using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.BinPoly
{
    /// <summary>
    /// Static entry point for binary-polynomial helpers. Reducer-independent ops
    /// (<see cref="Size"/>, <see cref="Create"/>, <c>Add</c>, <c>AddTo</c>) sit at the
    /// top level; <see cref="IBinPolyMul"/> factories classified by reduction
    /// polynomial shape live under the nested <see cref="Mul"/> sub-class, and inversion
    /// factories under <see cref="Inv"/> (Itoh-Tsujii today; safegcd a possible future sibling).
    /// </summary>
    /// <remarks>
    /// <para>This surface is assembly-<c>internal</c> — consumed by other Bouncy Castle code
    /// (the generic F2m field, BIKE, HQC), not a published API.</para>
    /// </remarks>
    internal static class BinPolys
    {
        /// <summary>
        /// Number of <c>ulong</c> limbs required to hold a polynomial of bit length <c>n</c>.
        /// </summary>
        public static int Size(int n) => (n + 63) >> 6;

        /// <summary>
        /// Allocate a fresh limb array of length <paramref name="size"/> (in <c>ulong</c>
        /// limbs, as returned by <see cref="Size"/>), initialised to zero. Caller-side bit-
        /// length-to-limb-count conversion sits at <see cref="Size"/>; this helper takes the
        /// already-converted limb count, matching the shape of <c>Add</c> / <c>AddTo</c>
        /// and the <c>Nat.Create64(int len)</c> convention.
        /// </summary>
        public static ulong[] Create(int size) => new ulong[size];

        /// <summary>
        /// Compute <c>z = x + y</c> as polynomial addition over <c>GF(2)</c> (limb-wise XOR).
        /// Independent of any reduction polynomial: degree-<c>&lt;n</c> stays degree-<c>&lt;n</c>
        /// automatically (no carry, no reduction). Operates on <paramref name="size"/>-limb slices
        /// starting at the given offsets.
        /// </summary>
        public static void Add(int size, ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z,
            int zOff)
        {
            Nat.Xor64(size, x, xOff, y, yOff, z, zOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="Add(int, ulong[], int, ulong[], int, ulong[], int)"/>.
        /// Operates on the first <paramref name="size"/> limbs of each span.
        /// </summary>
        public static void Add(int size, ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
        {
            Nat.Xor64(size, x, y, z);
        }
#endif

        /// <summary>
        /// Compute <c>z = z + x</c> as polynomial addition over <c>GF(2)</c> (limb-wise XOR into
        /// the accumulator). See <see cref="Add(int, ulong[], int, ulong[], int, ulong[], int)"/>
        /// for the reduction-independence rationale.
        /// </summary>
        public static void AddTo(int size, ulong[] x, int xOff, ulong[] z, int zOff)
        {
            Nat.XorTo64(size, x, xOff, z, zOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="AddTo(int, ulong[], int, ulong[], int)"/>.
        /// Operates on the first <paramref name="size"/> limbs of each span.
        /// </summary>
        public static void AddTo(int size, ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            Nat.XorTo64(size, x, z);
        }
#endif

        /// <summary>
        /// Copy a polynomial: <c>z[zOff..zOff + size] = x[xOff..xOff + size]</c>. No
        /// secret-wipe semantics — value-level move.
        /// </summary>
        public static void Copy(int size, ulong[] x, int xOff, ulong[] z, int zOff)
        {
            Array.Copy(x, xOff, z, zOff, size);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="Copy(int, ulong[], int, ulong[], int)"/>.
        /// </summary>
        public static void Copy(int size, ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            x.Slice(0, size).CopyTo(z);
        }
#endif

        /// <summary>
        /// Set the polynomial to the zero element of the ring: write <c>0</c> to every limb
        /// in <c>z[zOff..zOff + size]</c>. <b>Value-level</b> — for initialising accumulators
        /// and similar. The JIT may legitimately elide this write if the buffer becomes
        /// dead afterward (the *value* isn't observed). For wiping secret-bearing
        /// intermediate buffers, use <see cref="Clear(int, ulong[], int)"/> instead.
        /// </summary>
        public static void Zero(int size, ulong[] z, int zOff)
        {
            Array.Clear(z, zOff, size);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="Zero(int, ulong[], int)"/>.
        /// Value-level — see <see cref="Clear(int, Span{ulong})"/> for the secret-wipe
        /// variant.
        /// </summary>
        public static void Zero(int size, Span<ulong> z)
        {
            z.Slice(0, size).Clear();
        }
#endif

        /// <summary>
        /// <b>Secret-wipe</b>: actively erase <c>z[zOff..zOff + size]</c>. Forwards to
        /// <c>Arrays.ZeroMemory</c>, which is JIT-non-elidable by contract (via
        /// <c>CryptographicOperations.ZeroMemory</c> on .NET Core / 5+). Use this — not
        /// <see cref="Zero(int, ulong[], int)"/> — at sites where the buffer carried
        /// partial-product / key material that must be wiped under the project's
        /// side-channel discipline.
        /// </summary>
        public static void Clear(int size, ulong[] z, int zOff)
        {
            Arrays.ZeroMemory(z, zOff, size);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="Clear(int, ulong[], int)"/>.
        /// Secret-wipe with JIT-non-elision contract.
        /// </summary>
        public static void Clear(int size, Span<ulong> z)
        {
            Arrays.ZeroMemory(z.Slice(0, size));
        }
#endif

        /// <summary>
        /// Set the polynomial to <c>1</c> (the multiplicative identity in
        /// <c>GF(2)[x] / r(x)</c> for any <c>r(x)</c> with a non-zero constant term — true
        /// for all binomial / trinomial / pentanomial reductions this subsystem supports).
        /// This is <i>the polynomial 1</i> (low bit set, all other bits clear), not "all
        /// bits set". Value-level — see <see cref="Zero(int, ulong[], int)"/> for the rationale.
        /// </summary>
        public static void One(int size, ulong[] z, int zOff)
        {
            z[zOff] = 1UL;
            Array.Clear(z, zOff + 1, size - 1);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="One(int, ulong[], int)"/>.
        /// </summary>
        public static void One(int size, Span<ulong> z)
        {
            z[0] = 1UL;
            z.Slice(1, size - 1).Clear();
        }
#endif

        /// <summary>
        /// Constant-time equality test: returns <c>ulong.MaxValue</c> if
        /// <c>x[xOff..xOff + size]</c> equals <c>y[yOff..yOff + size]</c> limb-for-limb,
        /// and <c>0UL</c> otherwise. Forwards to <c>Nat.EqualTo64</c>; the bitwise OR
        /// across limbs makes the running cost independent of the data, so this is safe
        /// to use on secret-bearing polynomials.
        /// </summary>
        public static ulong EqualTo(int size, ulong[] x, int xOff, ulong[] y, int yOff)
        {
            return Nat.EqualTo64(size, x, xOff, y, yOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of
        /// <see cref="EqualTo(int, ulong[], int, ulong[], int)"/>. Operates on the first
        /// <paramref name="size"/> limbs of each span.
        /// </summary>
        public static ulong EqualTo(int size, ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y)
        {
            return Nat.EqualTo64(size, x, y);
        }
#endif

        /// <summary>
        /// Constant-time test for the multiplicative identity: returns <c>ulong.MaxValue</c> if
        /// <c>x[xOff..xOff + size]</c> is the polynomial <c>1</c> (low bit set, all other bits
        /// clear), and <c>0UL</c> otherwise. Forwards to <c>Nat.EqualToOne64</c>; the bitwise OR
        /// across limbs makes the running cost independent of the data, so this is safe to use on
        /// secret-bearing polynomials.
        /// </summary>
        public static ulong EqualToOne(int size, ulong[] x, int xOff)
        {
            return Nat.EqualToOne64(size, x, xOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="EqualToOne(int, ulong[], int)"/>. Tests the
        /// first <paramref name="size"/> limbs of <paramref name="x"/>.
        /// </summary>
        public static ulong EqualToOne(int size, ReadOnlySpan<ulong> x)
        {
            return Nat.EqualToOne64(size, x);
        }
#endif

        /// <summary>
        /// Constant-time test for the zero element: returns <c>ulong.MaxValue</c> if every limb of
        /// <c>x[xOff..xOff + size]</c> is zero, and <c>0UL</c> otherwise. Forwards to
        /// <c>Nat.EqualToZero64</c>; the bitwise OR across limbs makes the running cost independent
        /// of the data, so this is safe to use on secret-bearing polynomials.
        /// </summary>
        public static ulong EqualToZero(int size, ulong[] x, int xOff)
        {
            return Nat.EqualToZero64(size, x, xOff);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="EqualToZero(int, ulong[], int)"/>. Tests the
        /// first <paramref name="size"/> limbs of <paramref name="x"/>.
        /// </summary>
        public static ulong EqualToZero(int size, ReadOnlySpan<ulong> x)
        {
            return Nat.EqualToZero64(size, x);
        }
#endif

        /// <summary>
        /// <b>Variable-time</b> bit length of the polynomial in <c>x[xOff..xOff + size]</c>: the
        /// position of its most significant set bit plus one (i.e. degree + 1), or <c>0</c> for the
        /// zero polynomial. The <c>Var</c> suffix flags the data-dependent running time — it scans
        /// from the top limb down to the first non-zero one and takes that limb's leading-zero
        /// count — so it must not be used where the polynomial is secret and timing is observable.
        /// </summary>
        public static int BitLengthVar(int size, ulong[] x, int xOff)
        {
            int i = size;
            while (--i >= 0)
            {
                ulong x_i = x[xOff + i];
                if (x_i != 0UL)
                    return i * Longs.NumBits + Longs.BitLength(x_i);
            }
            return 0;
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        /// <summary>
        /// <see cref="Span{T}"/> overload of <see cref="BitLengthVar(int, ulong[], int)"/>. Examines
        /// the first <paramref name="size"/> limbs of <paramref name="x"/>.
        /// </summary>
        public static int BitLengthVar(int size, ReadOnlySpan<ulong> x)
        {
            int i = size;
            while (--i >= 0)
            {
                ulong x_i = x[i];
                if (x_i != 0UL)
                    return i * Longs.NumBits + Longs.BitLength(x_i);
            }
            return 0;
        }
#endif

        /// <summary>
        /// Factories for <see cref="IBinPolyMul"/> instances, classified by reduction
        /// polynomial shape: <see cref="Binomial"/> for <c>x^n + 1</c>,
        /// <see cref="Trinomial"/> for <c>x^n + x^k + 1</c>, and <see cref="Pentanomial"/>
        /// for <c>x^n + x^k3 + x^k2 + x^k1 + 1</c>.
        /// </summary>
        /// <remarks>
        /// The factories check parameter ranges and tap ordering but <b>not</b> irreducibility;
        /// callers attest to irreducibility by selecting the appropriate factory (a reducible
        /// polynomial yields defined-but-meaningless results).
        /// TODO: an evidence-of-validation wrapper type so external callers can be required to attest.
        /// </remarks>
        public static class Mul
        {
            /// <summary>
            /// Upper bound on the polynomial bit length <c>n</c>, enforced at factory time. The
            /// cap keeps all downstream limb-count and offset arithmetic provably within
            /// <c>int</c> range; it sits comfortably above the largest planned consumer
            /// (HQC-256 at ~58K bits).
            /// </summary>
            private const int MaxN = 1 << 20;

            /// <summary>Reduction by <c>x^n + 1</c> (cyclic ring, used by BIKE and HQC).</summary>
                public static IBinPolyMul Binomial(int n)
            {
                if (n < 1)
                    throw new ArgumentOutOfRangeException(nameof(n), "must be positive");
                // Even n is supported (e.g. the X9.62 c2pnb* curves have even m); BinomialReduce.Create
                // routes the n-multiple-of-64 case to a word-aligned reducer (z = low ^ high) and every
                // other n to the partial-top-limb reducer.
                if (n > MaxN)
                    throw new ArgumentOutOfRangeException(nameof(n), "must be at most 2^20");

                return CreateBinPolyMul(n, BinPolyMulBase.BinomialReduce.Create(n));
            }

            /// <summary>Reduction by <c>x^n + x^k + 1</c>.</summary>
                public static IBinPolyMul Trinomial(int n, int k)
            {
                if (n < 3)
                    throw new ArgumentOutOfRangeException(nameof(n), "must be at least 3");
                // Even n is supported. The word-at-a-time reducers (A/B/C families) rely on the
                // (n & 63) != 0 invariant (the (t << -s) modular-shift idiom corrupts at s_n = 0,
                // and the final mask ~(ulong.MaxValue << (n & 63)) would zero the result limb), so
                // TrinomialReduce.Create routes the n-multiple-of-64 case to the bitwise reducer D.
                if (n > MaxN)
                    throw new ArgumentOutOfRangeException(nameof(n), "must be at most 2^20");
                if (k < 1 || k >= n)
                    throw new ArgumentOutOfRangeException(nameof(k), "must satisfy 0 < k < n");

                return CreateBinPolyMul(n, BinPolyMulBase.TrinomialReduce.Create(n, k));
            }

            /// <summary>Reduction by <c>x^n + x^k3 + x^k2 + x^k1 + 1</c>.</summary>
                public static IBinPolyMul Pentanomial(int n, int k1, int k2, int k3)
            {
                if (n < 5)
                    throw new ArgumentOutOfRangeException(nameof(n), "must be at least 5");
                // Even n is supported (e.g. the X9.62 c2pnb* curves have even m). The word-at-a-time
                // reducers (A/B/D families) rely on the (n & 63) != 0 invariant (the (t << -s)
                // modular-shift idiom corrupts at s_n = 0, and the final mask
                // ~(ulong.MaxValue << (n & 63)) would zero the result limb), so PentanomialReduce.Create
                // routes the n-multiple-of-64 case to the bitwise reducer C.
                if (n > MaxN)
                    throw new ArgumentOutOfRangeException(nameof(n), "must be at most 2^20");
                if (k1 < 1 || k2 <= k1 || k3 <= k2 || k3 >= n)
                    throw new ArgumentException("must satisfy 0 < k1 < k2 < k3 < n");

                return CreateBinPolyMul(n, BinPolyMulBase.PentanomialReduce.Create(n, k1, k2, k3));
            }

            /// <summary>
            /// Dispatch from <c>(n, reducer)</c> to the first applicable backend's factory.
            /// Each backend exposes an <c>IsEnabled</c> gate (Scalar is the unconditional
            /// fallback) and a <c>CreateBinPolyMul</c> method that picks the most specialised
            /// <see cref="IBinPolyMul"/> for the requested size — the gate condition and the
            /// per-size dispatch both live inside the backend, not here.
            /// </summary>
            private static IBinPolyMul CreateBinPolyMul(int n, BinPolyMulBase.IReduce reduce)
            {
#if NETCOREAPP3_0_OR_GREATER
                if (X86.V128.Backend.IsEnabled)
                    return X86.V128.Backend.CreateBinPolyMul(n, reduce);
#endif
                return Scalar.Backend.CreateBinPolyMul(n, reduce);
            }
        }

        /// <summary>
        /// Factories for <see cref="IBinPolyInv"/> instances (multiplicative inversion in
        /// <c>GF(2^n)</c>), the inversion-specialised sibling of <see cref="Mul"/>.
        /// </summary>
        /// <remarks>
        /// Inversion requires a <b>field</b>: the reduction polynomial backing the <see cref="IBinPolyMul"/>
        /// passed to <see cref="ItohTsujii"/> must be irreducible. The binomial reducer (<c>x^n + 1</c>) is
        /// always reducible and must not be passed — see <see cref="IBinPolyInv"/>. A future
        /// <c>safegcd</c> factory would sit here as a drop-in sibling.
        /// </remarks>
        public static class Inv
        {
            /// <summary>
            /// Itoh–Tsujii inversion driving <paramref name="mul"/>'s arithmetic:
            /// <c>a^{-1} = a^(2^n - 2)</c> via an addition chain on <c>n - 1</c>. Valid for any
            /// <c>n</c> (even or odd) provided <paramref name="mul"/>'s reduction polynomial is
            /// irreducible.
            /// </summary>
                public static IBinPolyInv ItohTsujii(IBinPolyMul mul)
            {
                if (mul == null)
                    throw new ArgumentNullException(nameof(mul));
                if (mul.N < 2)
                    throw new ArgumentException("inversion requires a field of degree at least 2",
                        nameof(mul));

                return new ItohTsujiiInv(mul);
            }
        }
    }
}
