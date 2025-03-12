using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Math.Raw
{
    internal static class Nat384
    {
        public static void Mul(ReadOnlySpan<uint> x, ReadOnlySpan<uint> y, Span<uint> zz)
        {
            Nat192.Mul(x, y, zz);
            Nat192.Mul(x[6..], y[6..], zz[12..]);

            uint c18 = Nat192.AddToEachOther(zz[6..], zz[12..]);
            uint c12 = c18 + Nat192.AddTo(zz, zz[6..], 0);
            c18 += Nat192.AddTo(zz[18..], zz[12..], c12);

            uint[] dx = Nat192.Create(), dy = Nat192.Create();
            bool neg = Nat192.Diff(x[6..], x, dx) != Nat192.Diff(y[6..], y, dy);

            uint[] tt = Nat192.CreateExt();
            Nat192.Mul(dx, dy, tt);

            c18 += neg ? Nat.AddTo(12, tt, zz[6..]) : (uint)Nat.SubFrom(12, tt, zz[6..]);
            Nat.AddWordAt(24, c18, zz, 18);
        }

        public static void Square(ReadOnlySpan<uint> x, Span<uint> zz)
        {
            Nat192.Square(x, zz);
            Nat192.Square(x[6..], zz[12..]);

            uint c18 = Nat192.AddToEachOther(zz[6..], zz[12..]);
            uint c12 = c18 + Nat192.AddTo(zz, zz[6..], 0);
            c18 += Nat192.AddTo(zz[18..], zz[12..], c12);

            uint[] dx = Nat192.Create();
            Nat192.Diff(x[6..], x, dx);

            uint[] m = Nat192.CreateExt();
            Nat192.Square(dx, m);

            c18 += (uint)Nat.SubFrom(12, m, zz[6..]);
            Nat.AddWordAt(24, c18, zz, 18);
        }
    }
}
