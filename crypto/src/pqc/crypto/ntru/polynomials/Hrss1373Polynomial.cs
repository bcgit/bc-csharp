using System;

using Org.BouncyCastle.Pqc.Crypto.Ntru.ParameterSets;

namespace Org.BouncyCastle.Pqc.Crypto.Ntru.Polynomials
{
    internal class Hrss1373Polynomial
        : HrssPolynomial
    {
        private static readonly int L = ((1373 + 31) / 32) * 32;
        private static readonly int M = L / 4;
        private static readonly int K = L / 16;
        internal Hrss1373Polynomial(NtruHrssParameterSet parameters)
            : base(parameters)
        {
        }

        public override byte[] SqToBytes(int len)
        {
            byte[] r = new byte[len];

            int i, j;
#if NETCOREAPP2_0_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<short> t = stackalloc short[4];
#else
			short[] t = new short[4];
#endif
            for (i = 0; i < ParameterSet.PackDegree() / 4; i++)
            {
                for (j = 0; j < 4; j++)
                {
                    t[j] = (short)ModQ((uint)this.coeffs[4 * i + j] & 0xffff, (uint)ParameterSet.Q());
                }
                // t0 t1 t2 t3
                // r0 8
                // r1 6 | 2
                // r2 8
                // r3 4 | 4
                // r4 8
                // r5 2 | 6
                // r6 8
                r[7 * i + 0] = (byte)(t[0] & 0xff);
                r[7 * i + 1] = (byte)((t[0] >> 8) | ((t[1] & 0x03) << 6));
                r[7 * i + 2] = (byte)((t[1] >> 2) & 0xff);
                r[7 * i + 3] = (byte)((t[1] >> 10) | ((t[2] & 0x0f) << 4));
                r[7 * i + 4] = (byte)((t[2] >> 4) & 0xff);
                r[7 * i + 5] = (byte)((t[2] >> 12) | ((t[3] & 0x3f) << 2));
                r[7 * i + 6] = (byte)(t[3] >> 6);
            }
            // i=NtruPackDeg/4;
            if (ParameterSet.PackDegree() % 4 == 2)
            {
                t[0] = (short)ModQ((uint)this.coeffs[ParameterSet.PackDegree() - 2] & 0xffff, (uint)ParameterSet.Q());
                t[1] = (short)ModQ((uint)this.coeffs[ParameterSet.PackDegree() - 1] & 0xffff, (uint)ParameterSet.Q());
                r[7 * i + 0] = (byte)(t[0] & 0xff);
                r[7 * i + 1] = (byte)((t[0] >> 8) | ((t[1] & 0x03) << 6));
                r[7 * i + 2] = (byte)((t[1] >> 2) & 0xff);
                r[7 * i + 3] = (byte)(t[1] >> 10);
            }
            return r;
        }

        public override void SqFromBytes(byte[] a)

        {
            int i;
            for (i = 0; i < ParameterSet.PackDegree() / 4; i++)
            {
                this.coeffs[4 * i + 0] = (ushort)((a[7 * i + 0] & 0xff) | (((ushort)(a[7 * i + 1] & 0xff) & 0x3f) << 8));
                this.coeffs[4 * i + 1] = (ushort)(((a[7 * i + 1] & 0xff) >> 6) | (((ushort)(a[7 * i + 2] & 0xff)) << 2) | ((short)(a[7 * i + 3] & 0x0f) << 10));
                this.coeffs[4 * i + 2] = (ushort)(((a[7 * i + 3] & 0xff) >> 4) | (((ushort)(a[7 * i + 4] & 0xff) & 0xff) << 4) | ((short)(a[7 * i + 5] & 0x03) << 12));
                this.coeffs[4 * i + 3] = (ushort)(((a[7 * i + 5] & 0xff) >> 2) | (((ushort)(a[7 * i + 6] & 0xff)) << 6));
            }
            // i=NtruPackDeg/4;
            if (ParameterSet.PackDegree() % 4 == 2)
            {
                this.coeffs[4 * i + 0] = (ushort)(a[7 * i + 0] | ((a[7 * i + 1] & 0x3f) << 8));
                this.coeffs[4 * i + 1] = (ushort)((a[7 * i + 1] >> 6) | (((ushort)a[7 * i + 2]) << 2) | (((ushort)a[7 * i + 3] & 0x0f) << 10));
            }
            this.coeffs[ParameterSet.N - 1] = 0;
        }
    }

}
