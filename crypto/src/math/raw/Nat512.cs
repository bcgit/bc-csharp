using System;
#if NETCOREAPP3_0_OR_GREATER
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
#endif

namespace Org.BouncyCastle.Math.Raw
{
    internal static class Nat512
    {
        public static void Mul(uint[] x, uint[] y, uint[] zz)
        {
            Nat256.Mul(x, y, zz);
            Nat256.Mul(x, 8, y, 8, zz, 16);

            uint c24 = Nat256.AddToEachOther(zz, 8, zz, 16);
            uint c16 = c24 + Nat256.AddTo(zz, 0, zz, 8, 0U);
            c24 += Nat256.AddTo(zz, 24, zz, 16, c16);

            uint[] dx = Nat256.Create(), dy = Nat256.Create();
            bool neg = Nat256.Diff(x, 8, x, 0, dx, 0) != Nat256.Diff(y, 8, y, 0, dy, 0);

            uint[] tt = Nat256.CreateExt();
            Nat256.Mul(dx, dy, tt);

            c24 += neg ? Nat.AddTo(16, tt, 0, zz, 8) : (uint)Nat.SubFrom(16, tt, 0, zz, 8);
            Nat.AddWordAt(32, c24, zz, 24); 
        }

        public static void Square(uint[] x, uint[] zz)
        {
            Nat256.Square(x, zz);
            Nat256.Square(x, 8, zz, 16);

            uint c24 = Nat256.AddToEachOther(zz, 8, zz, 16);
            uint c16 = c24 + Nat256.AddTo(zz, 0, zz, 8, 0U);
            c24 += Nat256.AddTo(zz, 24, zz, 16, c16);

            uint[] dx = Nat256.Create();
            Nat256.Diff(x, 8, x, 0, dx, 0);

            uint[] m = Nat256.CreateExt();
            Nat256.Square(dx, m);

            c24 += (uint)Nat.SubFrom(16, m, 0, zz, 8);
            Nat.AddWordAt(32, c24, zz, 24); 
        }

        public static void Xor(uint[] x, uint[] y, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor(x.AsSpan(), y.AsSpan(), z.AsSpan());
#else
            for (int i = 0; i < 16; i += 4)
            {
                z[i + 0] = x[i + 0] ^ y[i + 0];
                z[i + 1] = x[i + 1] ^ y[i + 1];
                z[i + 2] = x[i + 2] ^ y[i + 2];
                z[i + 3] = x[i + 3] ^ y[i + 3];
            }
#endif
        }

        public static void Xor(uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
#else
            for (int i = 0; i < 16; i += 4)
            {
                z[zOff + i + 0] = x[xOff + i + 0] ^ y[yOff + i + 0];
                z[zOff + i + 1] = x[xOff + i + 1] ^ y[yOff + i + 1];
                z[zOff + i + 2] = x[xOff + i + 2] ^ y[yOff + i + 2];
                z[zOff + i + 3] = x[xOff + i + 3] ^ y[yOff + i + 3];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Xor(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..16]);
                var Y = MemoryMarshal.AsBytes(y[..16]);
                var Z = MemoryMarshal.AsBytes(z[..16]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
                var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

                var Z0 = Avx2.Xor(X0, Y0);
                var Z1 = Avx2.Xor(X1, Y1);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x20], in Z0);
                MemoryMarshal.Write(Z[0x20..0x40], in Z1);
#else
                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
#endif

                return;
            }

            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..16]);
                var Y = MemoryMarshal.AsBytes(y[..16]);
                var Z = MemoryMarshal.AsBytes(z[..16]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
                var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
                var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
                var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

                var Z0 = Sse2.Xor(X0, Y0);
                var Z1 = Sse2.Xor(X1, Y1);
                var Z2 = Sse2.Xor(X2, Y2);
                var Z3 = Sse2.Xor(X3, Y3);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x10], in Z0);
                MemoryMarshal.Write(Z[0x10..0x20], in Z1);
                MemoryMarshal.Write(Z[0x20..0x30], in Z2);
                MemoryMarshal.Write(Z[0x30..0x40], in Z3);
#else
                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
#endif
				return;
            }
#endif

				for ( int i = 0; i < 16; i += 4)
            {
                z[i + 0] = x[i + 0] ^ y[i + 0];
                z[i + 1] = x[i + 1] ^ y[i + 1];
                z[i + 2] = x[i + 2] ^ y[i + 2];
                z[i + 3] = x[i + 3] ^ y[i + 3];
            }
        }
#endif

        public static void Xor64(ulong[] x, ulong[] y, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor64(x.AsSpan(), y.AsSpan(), z.AsSpan());
#else
            for (int i = 0; i < 8; i += 4)
            {
                z[i + 0] = x[i + 0] ^ y[i + 0];
                z[i + 1] = x[i + 1] ^ y[i + 1];
                z[i + 2] = x[i + 2] ^ y[i + 2];
                z[i + 3] = x[i + 3] ^ y[i + 3];
            }
#endif
        }

        public static void Xor64(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Xor64(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
#else
            for (int i = 0; i < 8; i += 4)
            {
                z[zOff + i + 0] = x[xOff + i + 0] ^ y[yOff + i + 0];
                z[zOff + i + 1] = x[xOff + i + 1] ^ y[yOff + i + 1];
                z[zOff + i + 2] = x[xOff + i + 2] ^ y[yOff + i + 2];
                z[zOff + i + 3] = x[xOff + i + 3] ^ y[yOff + i + 3];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void Xor64(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Y = MemoryMarshal.AsBytes(y[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
                var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

                var Z0 = Avx2.Xor(X0, Y0);
                var Z1 = Avx2.Xor(X1, Y1);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x20], in Z0);
                MemoryMarshal.Write(Z[0x20..0x40], in Z1);
#else
                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
#endif
				return;
            }

            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Y = MemoryMarshal.AsBytes(y[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
                var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
                var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
                var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

                var Z0 = Sse2.Xor(X0, Y0);
                var Z1 = Sse2.Xor(X1, Y1);
                var Z2 = Sse2.Xor(X2, Y2);
                var Z3 = Sse2.Xor(X3, Y3);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x10], in Z0);
                MemoryMarshal.Write(Z[0x10..0x20], in Z1);
                MemoryMarshal.Write(Z[0x20..0x30], in Z2);
                MemoryMarshal.Write(Z[0x30..0x40], in Z3);
#else
                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
#endif
                return;
            }
#endif

				for ( int i = 0; i < 8; i += 4)
            {
                z[i + 0] = x[i + 0] ^ y[i + 0];
                z[i + 1] = x[i + 1] ^ y[i + 1];
                z[i + 2] = x[i + 2] ^ y[i + 2];
                z[i + 3] = x[i + 3] ^ y[i + 3];
            }
        }
#endif

        public static void XorBothTo(uint[] x, uint[] y, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorBothTo(x.AsSpan(), y.AsSpan(), z.AsSpan());
#else
            for (int i = 0; i < 16; i += 4)
            {
                z[i + 0] ^= x[i + 0] ^ y[i + 0];
                z[i + 1] ^= x[i + 1] ^ y[i + 1];
                z[i + 2] ^= x[i + 2] ^ y[i + 2];
                z[i + 3] ^= x[i + 3] ^ y[i + 3];
            }
#endif
        }

        public static void XorBothTo(uint[] x, int xOff, uint[] y, int yOff, uint[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorBothTo(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
#else
            for (int i = 0; i < 16; i += 4)
            {
                z[zOff + i + 0] ^= x[xOff + i + 0] ^ y[yOff + i + 0];
                z[zOff + i + 1] ^= x[xOff + i + 1] ^ y[yOff + i + 1];
                z[zOff + i + 2] ^= x[xOff + i + 2] ^ y[yOff + i + 2];
                z[zOff + i + 3] ^= x[xOff + i + 3] ^ y[yOff + i + 3];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void XorBothTo(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..16]);
                var Y = MemoryMarshal.AsBytes(y[..16]);
                var Z = MemoryMarshal.AsBytes(z[..16]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
                var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

                var Z0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
                var Z1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

                Z0 = Avx2.Xor(Z0, Avx2.Xor(X0, Y0));
                Z1 = Avx2.Xor(Z1, Avx2.Xor(X1, Y1));

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x20], in Z0);
                MemoryMarshal.Write(Z[0x20..0x40], in Z1);
#else
                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
#endif
				return;
            }

            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..16]);
                var Y = MemoryMarshal.AsBytes(y[..16]);
                var Z = MemoryMarshal.AsBytes(z[..16]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
                var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
                var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
                var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

                var Z0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
                var Z1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
                var Z2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
                var Z3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

                Z0 = Sse2.Xor(Z0, Sse2.Xor(X0, Y0));
                Z1 = Sse2.Xor(Z1, Sse2.Xor(X1, Y1));
                Z2 = Sse2.Xor(Z2, Sse2.Xor(X2, Y2));
                Z3 = Sse2.Xor(Z3, Sse2.Xor(X3, Y3));

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x10], in Z0);
                MemoryMarshal.Write(Z[0x10..0x20], in Z1);
                MemoryMarshal.Write(Z[0x20..0x30], in Z2);
                MemoryMarshal.Write(Z[0x30..0x40], in Z3);
#else
                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
#endif
                return;
            }
#endif

				for ( int i = 0; i < 16; i += 4)
            {
                z[i + 0] ^= x[i + 0] ^ y[i + 0];
                z[i + 1] ^= x[i + 1] ^ y[i + 1];
                z[i + 2] ^= x[i + 2] ^ y[i + 2];
                z[i + 3] ^= x[i + 3] ^ y[i + 3];
            }
        }
#endif

        public static void XorBothTo64(ulong[] x, ulong[] y, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorBothTo64(x.AsSpan(), y.AsSpan(), z.AsSpan());
#else
            for (int i = 0; i < 8; i += 4)
            {
                z[i + 0] ^= x[i + 0] ^ y[i + 0];
                z[i + 1] ^= x[i + 1] ^ y[i + 1];
                z[i + 2] ^= x[i + 2] ^ y[i + 2];
                z[i + 3] ^= x[i + 3] ^ y[i + 3];
            }
#endif
        }

        public static void XorBothTo64(ulong[] x, int xOff, ulong[] y, int yOff, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorBothTo64(x.AsSpan(xOff), y.AsSpan(yOff), z.AsSpan(zOff));
#else
            for (int i = 0; i < 8; i += 4)
            {
                z[zOff + i + 0] ^= x[xOff + i + 0] ^ y[yOff + i + 0];
                z[zOff + i + 1] ^= x[xOff + i + 1] ^ y[yOff + i + 1];
                z[zOff + i + 2] ^= x[xOff + i + 2] ^ y[yOff + i + 2];
                z[zOff + i + 3] ^= x[xOff + i + 3] ^ y[yOff + i + 3];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void XorBothTo64(ReadOnlySpan<ulong> x, ReadOnlySpan<ulong> y, Span<ulong> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Y = MemoryMarshal.AsBytes(y[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Y0 = MemoryMarshal.Read<Vector256<byte>>(Y[0x00..0x20]);
                var Y1 = MemoryMarshal.Read<Vector256<byte>>(Y[0x20..0x40]);

                var Z0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
                var Z1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

                Z0 = Avx2.Xor(Z0, Avx2.Xor(X0, Y0));
                Z1 = Avx2.Xor(Z1, Avx2.Xor(X1, Y1));

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x20], in Z0);
                MemoryMarshal.Write(Z[0x20..0x40], in Z1);
#else
                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
#endif
				return;
            }

            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Y = MemoryMarshal.AsBytes(y[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Y0 = MemoryMarshal.Read<Vector128<byte>>(Y[0x00..0x10]);
                var Y1 = MemoryMarshal.Read<Vector128<byte>>(Y[0x10..0x20]);
                var Y2 = MemoryMarshal.Read<Vector128<byte>>(Y[0x20..0x30]);
                var Y3 = MemoryMarshal.Read<Vector128<byte>>(Y[0x30..0x40]);

                var Z0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
                var Z1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
                var Z2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
                var Z3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

                Z0 = Sse2.Xor(Z0, Sse2.Xor(X0, Y0));
                Z1 = Sse2.Xor(Z1, Sse2.Xor(X1, Y1));
                Z2 = Sse2.Xor(Z2, Sse2.Xor(X2, Y2));
                Z3 = Sse2.Xor(Z3, Sse2.Xor(X3, Y3));

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x10], in Z0);
                MemoryMarshal.Write(Z[0x10..0x20], in Z1);
                MemoryMarshal.Write(Z[0x20..0x30], in Z2);
                MemoryMarshal.Write(Z[0x30..0x40], in Z3);
#else
                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
#endif
				return;
            }
#endif

            for (int i = 0; i < 8; i += 4)
            {
                z[i + 0] ^= x[i + 0] ^ y[i + 0];
                z[i + 1] ^= x[i + 1] ^ y[i + 1];
                z[i + 2] ^= x[i + 2] ^ y[i + 2];
                z[i + 3] ^= x[i + 3] ^ y[i + 3];
            }
        }
#endif

        public static void XorTo(uint[] x, uint[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo(x.AsSpan(), z.AsSpan());
#else
            for (int i = 0; i < 16; i += 4)
            {
                z[i + 0] ^= x[i + 0];
                z[i + 1] ^= x[i + 1];
                z[i + 2] ^= x[i + 2];
                z[i + 3] ^= x[i + 3];
            }
#endif
        }

        public static void XorTo(uint[] x, int xOff, uint[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo(x.AsSpan(xOff), z.AsSpan(zOff));
#else
            for (int i = 0; i < 16; i += 4)
            {
                z[zOff + i + 0] ^= x[xOff + i + 0];
                z[zOff + i + 1] ^= x[xOff + i + 1];
                z[zOff + i + 2] ^= x[xOff + i + 2];
                z[zOff + i + 3] ^= x[xOff + i + 3];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void XorTo(ReadOnlySpan<uint> x, Span<uint> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..16]);
                var Z = MemoryMarshal.AsBytes(z[..16]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Z0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
                var Z1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

                Z0 = Avx2.Xor(Z0, X0);
                Z1 = Avx2.Xor(Z1, X1);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x20], in Z0);
                MemoryMarshal.Write(Z[0x20..0x40], in Z1);
#else
                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
#endif
                return;
            }

            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..16]);
                var Z = MemoryMarshal.AsBytes(z[..16]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Z0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
                var Z1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
                var Z2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
                var Z3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

                Z0 = Sse2.Xor(Z0, X0);
                Z1 = Sse2.Xor(Z1, X1);
                Z2 = Sse2.Xor(Z2, X2);
                Z3 = Sse2.Xor(Z3, X3);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x10], in Z0);
                MemoryMarshal.Write(Z[0x10..0x20], in Z1);
                MemoryMarshal.Write(Z[0x20..0x30], in Z2);
                MemoryMarshal.Write(Z[0x30..0x40], in Z3);
#else
                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
#endif

                return;
            }
#endif

				for ( int i = 0; i < 16; i += 4)
            {
                z[i + 0] ^= x[i + 0];
                z[i + 1] ^= x[i + 1];
                z[i + 2] ^= x[i + 2];
                z[i + 3] ^= x[i + 3];
            }
        }
#endif

        public static void XorTo64(ulong[] x, ulong[] z)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo64(x.AsSpan(), z.AsSpan());
#else
            for (int i = 0; i < 8; i += 4)
            {
                z[i + 0] ^= x[i + 0];
                z[i + 1] ^= x[i + 1];
                z[i + 2] ^= x[i + 2];
                z[i + 3] ^= x[i + 3];
            }
#endif
        }

        public static void XorTo64(ulong[] x, int xOff, ulong[] z, int zOff)
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            XorTo64(x.AsSpan(xOff), z.AsSpan(zOff));
#else
            for (int i = 0; i < 8; i += 4)
            {
                z[zOff + i + 0] ^= x[xOff + i + 0];
                z[zOff + i + 1] ^= x[xOff + i + 1];
                z[zOff + i + 2] ^= x[xOff + i + 2];
                z[zOff + i + 3] ^= x[xOff + i + 3];
            }
#endif
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static void XorTo64(ReadOnlySpan<ulong> x, Span<ulong> z)
        {
#if NETCOREAPP3_0_OR_GREATER
            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Avx2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Y0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
                var Y1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

                var Z0 = Avx2.Xor(X0, Y0);
                var Z1 = Avx2.Xor(X1, Y1);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x20], in Z0);
                MemoryMarshal.Write(Z[0x20..0x40], in Z1);
#else
                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
#endif
                return;
            }

            if (Org.BouncyCastle.Runtime.Intrinsics.X86.Sse2.IsEnabled &&
                Org.BouncyCastle.Runtime.Intrinsics.Vector.IsPacked)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Y0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
                var Y1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
                var Y2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
                var Y3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

                var Z0 = Sse2.Xor(X0, Y0);
                var Z1 = Sse2.Xor(X1, Y1);
                var Z2 = Sse2.Xor(X2, Y2);
                var Z3 = Sse2.Xor(X3, Y3);

#if NET8_0_OR_GREATER
                MemoryMarshal.Write(Z[0x00..0x10], in Z0);
                MemoryMarshal.Write(Z[0x10..0x20], in Z1);
                MemoryMarshal.Write(Z[0x20..0x30], in Z2);
                MemoryMarshal.Write(Z[0x30..0x40], in Z3);
#else
                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
#endif

                return;
            }
#endif

				for ( int i = 0; i < 8; i += 4)
            {
                z[i + 0] ^= x[i + 0];
                z[i + 1] ^= x[i + 1];
                z[i + 2] ^= x[i + 2];
                z[i + 3] ^= x[i + 3];
            }
        }
#endif
    }
}
