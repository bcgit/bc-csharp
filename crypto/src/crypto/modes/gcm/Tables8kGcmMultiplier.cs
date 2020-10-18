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
                T = new ulong[32][];
            }
            else if (Arrays.AreEqual(this.H, H))
            {
                return;
            }

            this.H = Arrays.Clone(H);

            for (int i = 0; i < 32; ++i)
            {
                ulong[] t = T[i] = new ulong[32];

                // t[0] = 0

                if (i == 0)
                {
                    // t[1] = H.p^3
                    GcmUtilities.AsUlongs(this.H, t, 2);
                    GcmUtilities.MultiplyP3(t, 2, t, 2);
                }
                else
                {
                    // t[1] = T[i-1][1].p^4
                    GcmUtilities.MultiplyP4(T[i - 1], 2, t, 2);
                }

                for (int n = 2; n < 16; n += 2)
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
            //ulong[] z = new ulong[2];
            //for (int i = 15; i >= 0; --i)
            //{
            //    GcmUtilities.Xor(z, 0, T[i + i + 1], (x[i] & 0x0F) << 1);
            //    GcmUtilities.Xor(z, 0, T[i + i], (x[i] & 0xF0) >> 3);
            //}
            //Pack.UInt64_To_BE(z, x, 0);

            ulong z0 = 0, z1 = 0;

            for (int i = 15; i >= 0; --i)
            {
                ulong[] tu = T[i + i + 1], tv = T[i + i];
                int uPos = (x[i] & 0x0F) << 1, vPos = (x[i] & 0xF0) >> 3;

                z0 ^= tu[uPos + 0] ^ tv[vPos + 0];
                z1 ^= tu[uPos + 1] ^ tv[vPos + 1];
            }

            Pack.UInt64_To_BE(z0, x, 0);
            Pack.UInt64_To_BE(z1, x, 8);
        }
    }
}
