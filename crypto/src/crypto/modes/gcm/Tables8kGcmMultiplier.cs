using System;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Modes.Gcm
{
    public class Tables8kGcmMultiplier
        : IGcmMultiplier
    {
        private byte[] H;
        private ulong[][] T;

        public void Init(byte[] H)
        {
            if (T == null)
            {
                T = new ulong[2][];
            }
            else if (Arrays.AreEqual(this.H, H))
            {
                return;
            }

            this.H = Arrays.Clone(H);

            for (int i = 0; i < 2; ++i)
            {
                ulong[] t = T[i] = new ulong[512];

                // t[0] = 0

                if (i == 0)
                {
                    // t[1] = H.p^7
                    GcmUtilities.AsUlongs(this.H, t, 2);
                    GcmUtilities.MultiplyP7(t, 2, t, 2);
                }
                else
                {
                    // t[1] = T[i-1][1].p^8
                    GcmUtilities.MultiplyP8(T[i - 1], 2, t, 2);
                }

                for (int n = 2; n < 256; n += 2)
                {
                    // t[2.n] = t[n].p^-1
                    GcmUtilities.DivideP(t, n, t, n << 1);

                    // t[2.n + 1] = t[2.n] + t[1]
                    GcmUtilities.Xor(t, n << 1, t, 2, t, (n + 1) << 1);
                }
            }
        }

        public void MultiplyH(byte[] x)
        {
            ulong[] T0 = T[0], T1 = T[1];

            //ulong[] z = new ulong[2];
            //for (int i = 14; i >= 0; i -= 2)
            //{
            //    GcmUtilities.MultiplyP16(z);
            //    GcmUtilities.Xor(z, 0, T0, x[i] << 1);
            //    GcmUtilities.Xor(z, 0, T1, x[i + 1] << 1);
            //}
            //Pack.UInt64_To_BE(z, x, 0);

            int vPos = x[15] << 1;
            int uPos = x[14] << 1;
            ulong z1 = T0[uPos + 1] ^ T1[vPos + 1];
            ulong z0 = T0[uPos] ^ T1[vPos];

            for (int i = 12; i >= 0; i -= 2)
            {
                vPos = x[i + 1] << 1;
                uPos = x[i] << 1;

                ulong c = z1 << 48;
                z1 = T0[uPos + 1] ^ T1[vPos + 1] ^ ((z1 >> 16) | (z0 << 48));
                z0 = T0[uPos] ^ T1[vPos] ^ (z0 >> 16) ^ c ^ (c >> 1) ^ (c >> 2) ^ (c >> 7);
            }

            Pack.UInt64_To_BE(z0, x, 0);
            Pack.UInt64_To_BE(z1, x, 8);
        }
    }
}
