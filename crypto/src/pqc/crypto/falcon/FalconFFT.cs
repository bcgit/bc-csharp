namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal static class FalconFft
    {
        /*
        * License from the reference C code (the code was copied then modified
        * to function in C#):
        * ==========================(LICENSE BEGIN)============================
        *
        * Copyright (c) 2017-2019  Falcon Project
        *
        * Permission is hereby granted, free of charge, to any person obtaining
        * a copy of this software and associated documentation files (the
        * "Software"), to deal in the Software without restriction, including
        * without limitation the rights to use, copy, modify, merge, publish,
        * distribute, sublicense, and/or sell copies of the Software, and to
        * permit persons to whom the Software is furnished to do so, subject to
        * the following conditions:
        *
        * The above copyright notice and this permission notice shall be
        * included in all copies or substantial portions of the Software.
        *
        * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
        * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
        * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
        * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
        * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
        * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
        * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
        *
        * ===========================(LICENSE END)=============================
        */

        /*
         * Let w = exp(i*pi/N); w is a primitive 2N-th root of 1. We define the values w_j = w^(2j+1) for all j from 0
         * to N-1: these are the roots of X^N+1 in the field of complex numbers. A crucial property is that
         * w_{N-1-j} = conj(w_j) = 1/w_j for all j.
         *
         * FFT representation of a polynomial f (taken modulo X^N+1) is the set of values f(w_j). Since f is real,
         * conj(f(w_j)) = f(conj(w_j)), thus f(w_{N-1-j}) = conj(f(w_j)). We thus store only half the values,
         * for j = 0 to N/2-1; the other half can be recomputed easily when (if) needed. A consequence is that FFT
         * representation has the same size as normal representation: N/2 complex numbers use N real numbers (each
         * complex number is the combination of a real and an imaginary part).
         *
         * We use a specific ordering which makes computations easier. Let rev() be the bit-reversal function over logN
         * bits. For j in 0..N/2-1, we store the real and imaginary parts of f(w_j) in slots:
         *
         *    Re(f(w_j)) -> slot rev(j)/2
         *    Im(f(w_j)) -> slot rev(j)/2+N/2
         *
         * (Note that rev(j) is even for j < N/2.)
         */
        internal static void Fft(FalconFpr[] fsrc, int f, int logN)
        {
            /*
             * FFT algorithm in bit-reversal order uses the following iterative algorithm:
             *
             *   t = N
             *   for m = 1; m < N; m *= 2:
             *       ht = t/2
             *       for i1 = 0; i1 < m; i1 ++:
             *           j1 = i1 * t
             *           s = GM[m + i1]
             *           for j = j1; j < (j1 + ht); j ++:
             *               x = fsrc[f + j]
             *               y = s * fsrc[f + j + ht]
             *               fsrc[f + j] = x + y
             *               fsrc[f + j + ht] = x - y
             *       t = ht
             *
             * GM[k] contains w^rev(k) for primitive root w = exp(i*pi/N).
             *
             * In the description above, fsrc[f + ] is supposed to contain complex numbers. In our in-memory
             * representation, the real and imaginary parts of fsrc[f + k] are in array slots k and k+N/2.
             *
             * We only keep the first half of the complex numbers. We can see that after the first iteration, the first
             * and second halves of the array of complex numbers have separate lives, so we simply ignore the second
             * part.
             */

            /*
             * First iteration: compute fsrc[f + j] + i * fsrc[f + j+N/2] for all j < N/2
             * (because GM[1] = w^rev(1) = w^(N/2) = i).
             * In our chosen representation, this is a no-op: everything is already where it should be.
             */

            // Subsequent iterations are truncated to use only the first half of values.

            int n = 1 << logN;
            int hn = n >> 1;
            int t = hn;
            int m = 2;
            for (int u = 1; u < logN; ++u, m <<= 1)
            {
                int ht = t >> 1;
                int hm = m >> 1;
                for (int i1 = 0, j1 = 0; i1 < hm; ++i1, j1 += t)
                {
                    int j2 = j1 + ht;
                    var s = new FalconFpc(
                        FprEngine.FprGMTab[((m + i1) << 1) + 0],
                        FprEngine.FprGMTab[((m + i1) << 1) + 1]);
                    for (int j = j1; j < j2; ++j)
                    {
                        var x = new FalconFpc(fsrc[f + j], fsrc[f + j + hn]);
                        var y = FalconFpc.Mul(new FalconFpc(fsrc[f + j + ht], fsrc[f + j + ht + hn]), s);
                        var z = FalconFpc.Add(x, y);
                        fsrc[f + j] = z.Re; fsrc[f + j + hn] = z.Im;
                        z = FalconFpc.Sub(x, y);
                        fsrc[f + j + ht] = z.Re; fsrc[f + j + ht + hn] = z.Im;
                    }
                }
                t = ht;
            }
        }

        internal static void InvFft(FalconFpr[] fsrc, int f, int logN)
        {
            /*
             * Inverse FFT algorithm in bit-reversal order uses the following iterative algorithm:
             *
             *   t = 1
             *   for m = N; m > 1; m /= 2:
             *       hm = m/2
             *       dt = t*2
             *       for i1 = 0; i1 < hm; i1 ++:
             *           j1 = i1 * dt
             *           s = iGM[hm + i1]
             *           for j = j1; j < (j1 + t); j ++:
             *               x = fsrc[f + j]
             *               y = fsrc[f + j + t]
             *               fsrc[f + j] = x + y
             *               fsrc[f + j + t] = s * (x - y)
             *       t = dt
             *   for i1 = 0; i1 < N; i1 ++:
             *       fsrc[f + i1] = fsrc[f + i1] / N
             *
             * iGM[k] contains (1/w)^rev(k) for primitive root w = exp(i*pi/N)
             * (actually, iGM[k] = 1/GM[k] = conj(GM[k])).
             *
             * In the main loop (not counting the final division loop), in all iterations except the last, the first and
             * second half of fsrc[f + ] (as an array of complex numbers) are separate. In our chosen representation, we
             * do not keep the second half.
             *
             * The last iteration recombines the recomputed half with the implicit half, and should yield only real
             * numbers since the target polynomial is real; moreover, s = i at that step.
             * Thus, when considering x and y:
             *    y = conj(x) since the final fsrc[f + j] must be real
             * Therefore, fsrc[f + j] is filled with 2*Re(x), and fsrc[f + j + t] is filled with 2*Im(x).
             *
             * But we already have Re(x) and Im(x) in array slots j and j + t in our chosen representation. That last
             * iteration is thus a simple doubling of the values in all the array.
             *
             * We make the last iteration a no-op by tweaking the final division into a division by N/2, not N.
             */
            int n = 1 << logN;
            int t = 1;
            int m = n;
            int hn = n >> 1;
            for (int u = logN; u > 1; --u)
            {
                int hm = m >> 1;
                int dt = t << 1;
                for (int i1 = 0, j1 = 0; j1 < hn; ++i1, j1 += dt)
                {
                    int j2 = j1 + t;
                    var s = FalconFpc.Conj(new FalconFpc(
                        FprEngine.FprGMTab[((hm + i1) << 1) + 0],
                        FprEngine.FprGMTab[((hm + i1) << 1) + 1]));
                    for (int j = j1; j < j2; ++j)
                    {
                        var x = new FalconFpc(fsrc[f + j], fsrc[f + j + hn]);
                        var y = new FalconFpc(fsrc[f + j + t], fsrc[f + j + t + hn]);
                        var z = FalconFpc.Add(x, y);
                        fsrc[f + j] = z.Re; fsrc[f + j + hn] = z.Im;

                        z = FalconFpc.Mul(FalconFpc.Sub(x, y), s);
                        fsrc[f + j + t] = z.Re; fsrc[f + j + t + hn] = z.Im;
                    }
                }
                t = dt;
                m = hm;
            }

            /*
             * Last iteration is a no-op, provided that we divide by N/2 instead of N.
             * We need to make a special case for logN = 0.
             */
            if (logN > 0)
            {
                FalconFpr ni = FprEngine.FprP2Tab[logN];
                for (int u = 0; u < n; ++u)
                {
                    fsrc[f + u] = FprEngine.FprMul(fsrc[f + u], ni);
                }
            }
        }

        internal static void PolyAdd(FalconFpr[] asrc, int a, FalconFpr[] bsrc, int b, int logN)
        {
            int n = 1 << logN;
            for (int u = 0; u < n; ++u)
            {
                asrc[a + u] = FprEngine.FprAdd(asrc[a + u], bsrc[b + u]);
            }
        }

        internal static void PolySub(FalconFpr[] asrc, int a, FalconFpr[] bsrc, int b, int logN)
        {
            int n = 1 << logN;
            for (int u = 0; u < n; ++u)
            {
                asrc[a + u] = FprEngine.FprSub(asrc[a + u], bsrc[b + u]);
            }
        }

        internal static void PolyNeg(FalconFpr[] asrc, int a, int logN)
        {
            int n = 1 << logN;
            for (int u = 0; u < n; ++u)
            {
                asrc[a + u] = FprEngine.FprNeg(asrc[a + u]);
            }
        }

        internal static void PolyAdjFft(FalconFpr[] asrc, int a, int logN)
        {
            int n = 1 << logN;
            for (int u = (n >> 1); u < n; ++u)
            {
                asrc[a + u] = FprEngine.FprNeg(asrc[a + u]);
            }
        }

        internal static void PolyMulFft(FalconFpr[] asrc, int a, FalconFpr[] bsrc, int b, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                var x = new FalconFpc(asrc[a + u], asrc[a + u + hn]);
                var y = new FalconFpc(bsrc[b + u], bsrc[b + u + hn]);
                var z = FalconFpc.Mul(x, y);
                asrc[a + u] = z.Re; asrc[a + u + hn] = z.Im;
            }
        }

        internal static void PolyMulAdjFft(FalconFpr[] asrc, int a, FalconFpr[] bsrc, int b, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                var x = new FalconFpc(asrc[a + u], asrc[a + u + hn]);
                var y = FalconFpc.Conj(new FalconFpc(bsrc[b + u], bsrc[b + u + hn]));
                var z = FalconFpc.Mul(x, y);
                asrc[a + u] = z.Re; asrc[a + u + hn] = z.Im;
            }
        }

        internal static void PolyMulSelfAdjFft(FalconFpr[] asrc, int a, int logN)
        {
            // Since each coefficient is multiplied with its own conjugate, the result contains only real values.

            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                FalconFpr a_re = asrc[a + u];
                FalconFpr a_im = asrc[a + u + hn];
                asrc[a + u] = FprEngine.FprAdd(FprEngine.FprSqr(a_re), FprEngine.FprSqr(a_im));
                asrc[a + u + hn] = FprEngine.FprZero;
            }
        }

        internal static void PolyMulConst(FalconFpr[] asrc, int a, FalconFpr x, int logN)
        {
            int n = 1 << logN;
            for (int u = 0; u < n; ++u)
            {
                asrc[a + u] = FprEngine.FprMul(asrc[a + u], x);
            }
        }

        //internal static void poly_div_fft(FalconFPR[] asrc, int a, FalconFPR[] bsrc, int b, int logN)
        //{
        //    int n = 1 << logN;
        //    int hn = n >> 1;
        //    for (int u = 0; u < hn; ++u)
        //    {
        //        FalconFPR a_re = asrc[a + u];
        //        FalconFPR a_im = asrc[a + u + hn];
        //        FalconFPR b_re = bsrc[b + u];
        //        FalconFPR b_im = bsrc[b + u + hn];
        //        FalconFPR[] res = FPC_DIV(a_re, a_im, b_re, b_im);
        //        asrc[a + u] = res[0]; asrc[a + u + hn] = res[1];
        //    }
        //}

        internal static void PolyInvNorm2Fft(FalconFpr[] dsrc, int d, FalconFpr[] asrc, int a, FalconFpr[] bsrc,
            int b, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                FalconFpr a_re = asrc[a + u];
                FalconFpr a_im = asrc[a + u + hn];
                FalconFpr b_re = bsrc[b + u];
                FalconFpr b_im = bsrc[b + u + hn];
                dsrc[d + u] = FprEngine.FprInv(FprEngine.FprAdd(
                    FprEngine.FprAdd(FprEngine.FprSqr(a_re), FprEngine.FprSqr(a_im)),
                    FprEngine.FprAdd(FprEngine.FprSqr(b_re), FprEngine.FprSqr(b_im))));
            }
        }

        internal static void PolyAddMulAdjFft(FalconFpr[] dsrc, int d, FalconFpr[] Fsrc, int F, FalconFpr[] Gsrc,
            int G, FalconFpr[] fsrc, int f, FalconFpr[] gsrc, int g, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                var zF = FalconFpc.Mul(
                    new FalconFpc(Fsrc[F + u], Fsrc[F + u + hn]),
                    FalconFpc.Conj(new FalconFpc(fsrc[f + u], fsrc[f + u + hn])));
                var zG = FalconFpc.Mul(
                    new FalconFpc(Gsrc[G + u], Gsrc[G + u + hn]),
                    FalconFpc.Conj(new FalconFpc(gsrc[g + u], gsrc[g + u + hn])));
                var z = FalconFpc.Add(zF, zG);
                dsrc[d + u] = z.Re;
                dsrc[d + u + hn] = z.Im;
            }
        }

        internal static void PolyMulAutoAdjFft(FalconFpr[] asrc, int a, FalconFpr[] bsrc, int b, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                asrc[a + u] = FprEngine.FprMul(asrc[a + u], bsrc[b + u]);
                asrc[a + u + hn] = FprEngine.FprMul(asrc[a + u + hn], bsrc[b + u]);
            }
        }

        internal static void PolyDivAutoAdjFft(FalconFpr[] asrc, int a, FalconFpr[] bsrc, int b, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                FalconFpr ib = FprEngine.FprInv(bsrc[b + u]);
                asrc[a + u] = FprEngine.FprMul(asrc[a + u], ib);
                asrc[a + u + hn] = FprEngine.FprMul(asrc[a + u + hn], ib);
            }
        }

        internal static void PolyLdlFft(FalconFpr[] g00src, int g00, FalconFpr[] g01src, int g01, FalconFpr[] g11src,
            int g11, int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            for (int u = 0; u < hn; ++u)
            {
                var c00 = new FalconFpc(g00src[g00 + u], g00src[g00 + u + hn]);
                var c01 = new FalconFpc(g01src[g01 + u], g01src[g01 + u + hn]);
                var c11 = new FalconFpc(g11src[g11 + u], g11src[g11 + u + hn]);
                var mu = FalconFpc.Div(c01, c00);
                var z = FalconFpc.Sub(c11, FalconFpc.Mul(mu, FalconFpc.Conj(c01)));
                g11src[g11 + u] = z.Re; g11src[g11 + u + hn] = z.Im;
                g01src[g01 + u] = mu.Re;
                g01src[g01 + u + hn] = FprEngine.FprNeg(mu.Im);
            }
        }

        //internal static void poly_LDLmv_fft(FalconFPR[] d11src, int d11, FalconFPR[] l10src, int l10,
        //    FalconFPR[] g00src, int g00, FalconFPR[] g01src, int g01, FalconFPR[] g11src, int g11, int logN)
        //{
        //    int n = 1 << logN;
        //    int hn = n >> 1;
        //    for (int u = 0; u < hn; ++u)
        //    {
        //        FalconFPR g00_re = g00src[g00 + u];
        //        FalconFPR g00_im = g00src[g00 + u + hn];
        //        FalconFPR g01_re = g01src[g01 + u];
        //        FalconFPR g01_im = g01src[g01 + u + hn];
        //        FalconFPR g11_re = g11src[g11 + u];
        //        FalconFPR g11_im = g11src[g11 + u + hn];
        //        FalconFPR[] res = FPC_DIV(g01_re, g01_im, g00_re, g00_im);
        //        FalconFPR mu_re = res[0], mu_im = res[1];
        //        res = FPC_MUL(mu_re, mu_im, g01_re, FprEngine.fpr_neg(g01_im));
        //        g01_re = res[0]; g01_im = res[1];
        //        res = FPC_SUB(g11_re, g11_im, g01_re, g01_im);
        //        d11src[d11 + u] = res[0]; d11src[d11 + u + hn] = res[1];
        //        l10src[l10 + u] = mu_re;
        //        l10src[l10 + u + hn] = FprEngine.fpr_neg(mu_im);
        //    }
        //}

        internal static void PolySplitFft(FalconFpr[] f0src, int f0, FalconFpr[] f1src, int f1, FalconFpr[] fsrc,
            int f, int logN)
        {
            /*
             * The FFT representation we use is in bit-reversed order (element i contains f(w^(rev(i))), where rev() is
             * the bit-reversal function over the ring degree. This changes indexes with regards to the Falcon
             * specification.
             */
            int n = 1 << logN;
            int hn = n >> 1;
            int qn = hn >> 1;

            /*
             * We process complex values by pairs. For logN = 1, there is only one complex value (the other one is the
             * implicit conjugate), so we add the two lines below because the loop will be skipped.
             */
            f0src[f0 + 0] = fsrc[f + 0];
            f1src[f1 + 0] = fsrc[f + hn];

            for (int u = 0; u < qn; ++u)
            {
                var a = new FalconFpc(fsrc[f + (u << 1) + 0], fsrc[f + (u << 1) + 0 + hn]);
                var b = new FalconFpc(fsrc[f + (u << 1) + 1], fsrc[f + (u << 1) + 1 + hn]);

                var t = FalconFpc.Add(a, b);
                f0src[f0 + u] = FprEngine.FprHalf(t.Re);
                f0src[f0 + u + qn] = FprEngine.FprHalf(t.Im);

                t = FalconFpc.Mul(FalconFpc.Sub(a, b), FalconFpc.Conj(new FalconFpc(
                    FprEngine.FprGMTab[((u + hn) << 1) + 0],
                    FprEngine.FprGMTab[((u + hn) << 1) + 1])));
                f1src[f1 + u] = FprEngine.FprHalf(t.Re);
                f1src[f1 + u + qn] = FprEngine.FprHalf(t.Im);
            }
        }

        internal static void PolyMergeFft(FalconFpr[] fsrc, int f, FalconFpr[] f0src, int f0, FalconFpr[] f1src, int f1,
            int logN)
        {
            int n = 1 << logN;
            int hn = n >> 1;
            int qn = hn >> 1;

            // An extra copy to handle the special case logN = 1.

            fsrc[f + 0] = f0src[f0 + 0];
            fsrc[f + hn] = f1src[f1 + 0];

            for (int u = 0; u < qn; ++u)
            {
                var a = new FalconFpc(f0src[f0 + u], f0src[f0 + u + qn]);
                var b = FalconFpc.Mul(new FalconFpc(f1src[f1 + u], f1src[f1 + u + qn]), new FalconFpc(
                    FprEngine.FprGMTab[((u + hn) << 1) + 0],
                    FprEngine.FprGMTab[((u + hn) << 1) + 1]));
                var t = FalconFpc.Add(a, b);
                fsrc[f + (u << 1) + 0] = t.Re;
                fsrc[f + (u << 1) + 0 + hn] = t.Im;
                t = FalconFpc.Sub(a, b);
                fsrc[f + (u << 1) + 1] = t.Re;
                fsrc[f + (u << 1) + 1 + hn] = t.Im;
            }
        }
    }
}
