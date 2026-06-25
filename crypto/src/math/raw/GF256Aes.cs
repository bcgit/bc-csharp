namespace Org.BouncyCastle.Math.Raw
{
    internal static class GF256Aes
    {
        internal static int Mul(int a, int b)
        {
            b &= 0xFF;

            int c = (b << 4) & -(a & 0x10)
                  ^ (b << 5) & -(a & 0x20)
                  ^ (b << 6) & -(a & 0x40)
                  ^ (b << 7) & -(a & 0x80);
            int d = (b << 0) & -(a & 0x01)
                  ^ (b << 1) & -(a & 0x02)
                  ^ (b << 2) & -(a & 0x04)
                  ^ (b << 3) & -(a & 0x08);

            int e = c >> 8;
            e ^= e << 1;
            e ^= e << 3;
            d ^= e;

            int f = d >> 8; d = (d ^ c) & 0xFF;
            f ^= f << 1;
            f ^= f << 3;
            d ^= f;

            return d;
        }

        internal static int Sqr(int a)
        {
            int c = (int)Interleave.Expand4to8((byte)a);
            int hi = 0x1B00 & -(a & 0x10)
                   ^ 0x6C00 & -(a & 0x20)
                   ^ 0xAB00 & -(a & 0x40)
                   ^ 0x9A00 & -(a & 0x80);
            return c ^ (hi >> 8);
        }

        internal static int Inv(int a)
        {
            a &= 0xFF;
            int a2 = Sqr(a);
            int a4 = Sqr(a2);
            int a8 = Sqr(a4);
            int a6 = Mul(a4, a2);
            int a14 = Mul(a8, a6);
            int a28 = Sqr(a14);
            int a56 = Sqr(a28);
            int a112 = Sqr(a56);
            int a126 = Mul(a112, a14);
            int a252 = Sqr(a126);
            int a254 = Mul(a252, a2);
            // a^254 = a^-1
            return a254;
        }
    }
}
