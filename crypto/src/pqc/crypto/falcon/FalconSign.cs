using System;

using Org.BouncyCastle.Crypto.Digests;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    internal static class FalconSign
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
        * Binary case:
        *   N = 2^logn
        *   phi = X^N+1
        */

        /*
        * Get the size of the LDL tree for an input with polynomials of size
        * 2^logn. The size is expressed in the number of elements.
        */
        //internal static uint ffLDL_treesize(int logN)
        //{
        //    /*
        //    * For logn = 0 (polynomials are constant), the "tree" is a
        //    * single element. Otherwise, the tree node has size 2^logn, and
        //    * has two child trees for size logn-1 each. Thus, treesize s()
        //    * must fulfill these two relations:
        //    *
        //    *   s(0) = 1
        //    *   s(logN) = (2^logN) + 2*s(logN-1)
        //    */
        //    return (logN + 1) << logN;
        //}

        /*
        * Inner function for ffLDL_fft(). It expects the matrix to be both
        * auto-adjoint and quasicyclic; also, it uses the source operands
        * as modifiable temporaries.
        *
        * tmp[] must have room for at least one polynomial.
        */
        //internal static void ffLDL_fft_inner(FalconFPR[] treesrc, int tree, FalconFPR[] g0src, int g0,
        //    FalconFPR[] g1src, int g1, int logN, FalconFPR[] tmpsrc, int tmp)
        //{
        //    int n = 1 << logN;
        //    if (n == 1)
        //    {
        //        treesrc[tree + 0] = g0src[g0 + 0];
        //        return;
        //    }
        //    int hn = n >> 1;

        //    /*
        //    * The LDL decomposition yields L (which is written in the tree)
        //    * and the diagonal of D. Since d00 = g0, we just write d11
        //    * into tmp.
        //    */
        //    this.ffte.poly_LDLmv_fft(tmpsrc, tmp, treesrc, tree, g0src, g0, g1src, g1, g0src, g0, logN);

        //    /*
        //    * Split d00 (currently in g0) and d11 (currently in tmp). We
        //    * reuse g0 and g1 as temporary storage spaces:
        //    *   d00 splits into g1, g1+hn
        //    *   d11 splits into g0, g0+hn
        //    */
        //    this.ffte.poly_split_fft(g1src, g1, g1src, g1 + hn, g0src, g0, logN);
        //    this.ffte.poly_split_fft(g0src, g0, g0src, g0 + hn, tmpsrc, tmp, logN);

        //    /*
        //    * Each split result is the first row of a new auto-adjoint
        //    * quasicyclic matrix for the next recursive step.
        //    */
        //    ffLDL_fft_inner(treesrc, tree + n, g1src, g1, g1src, g1 + hn, logn - 1, tmpsrc, tmp);
        //    ffLDL_fft_inner(treesrc, tree + n + (int)ffLDL_treesize(logn - 1), g0src, g0, g0src, g0 + hn, logN - 1,
        //        tmpsrc, tmp);
        //}

        /*
        * Compute the ffLDL tree of an auto-adjoint matrix G. The matrix
        * is provided as three polynomials (FFT representation).
        *
        * The "tree" array is filled with the computed tree, of size
        * (logn+1)*(2^logn) elements (see ffLDL_treesize()).
        *
        * Input arrays MUST NOT overlap, except possibly the three unmodified
        * arrays g00, g01 and g11. tmp[] should have room for at least three
        * polynomials of 2^logn elements each.
        */
        //internal static void ffLDL_fft(FalconFPR[] treesrc, int tree, FalconFPR[] g00src, int g00, FalconFPR[] g01src,
        //    int g01, FalconFPR[] g11src, int g11, int logN, FalconFPR[] tmpsrc, int tmp)
        //{
        //    int n = 1 << logN;
        //    if (n == 1)
        //    {
        //        treesrc[tree + 0] = g00src[g00 + 0];
        //        return;
        //    }
        //    int hn = n >> 1;
        //    int d00 = tmp;
        //    int d11 = tmp + n;
        //    tmp += n << 1;

        //    Array.Copy(g00src, g00, tmpsrc, d00, n);
        //    this.ffte.poly_LDLmv_fft(tmpsrc, d11, treesrc, tree, g00src, g00, g01src, g01, g11src, g11, logN);

        //    this.ffte.poly_split_fft(tmpsrc, tmp, tmpsrc, tmp + hn, tmpsrc, d00, logN);
        //    this.ffte.poly_split_fft(tmpsrc, d00, tmpsrc, d00 + hn, tmpsrc, d11, logN);
        //    Array.Copy(tmpsrc, tmp, tmpsrc, d11, n);
        //    ffLDL_fft_inner(treesrc, tree + n, tmpsrc, d11, tmpsrc, d11 + hn, logN - 1, tmpsrc, tmp);
        //    ffLDL_fft_inner(treesrc, tree + n + (int)ffLDL_treesize(logN - 1), tmpsrc, d00, tmpsrc, d00 + hn, logN - 1,
        //        tmpsrc, tmp);
        //}

        /*
        * Normalize an ffLDL tree: each leaf of value x is replaced with
        * sigma / sqrt(x).
        */
        //internal static void ffLDL_binary_normalize(FalconFPR[] treesrc, int tree, int origLogN, int logN)
        //{
        //    /*
        //    * TODO: make an iterative version.
        //    */

        //    int n = 1 << logN;
        //    if (n == 1)
        //    {
        //        /*
        //        * We actually store in the tree leaf the inverse of
        //        * the value mandated by the specification: this
        //        * saves a division both here and in the sampler.
        //        */
        //        treesrc[tree + 0] = FprEngine.fpr_mul(FprEngine.fpr_sqrt(treesrc[tree + 0]),
        //            FprEngine.fpr_inv_sigma[origLogN]);
        //    }
        //    else
        //    {
        //        ffLDL_binary_normalize(treesrc, tree + n, origLogN, logN - 1);
        //        ffLDL_binary_normalize(treesrc, tree + n + (int)ffLDL_treesize(logN - 1), origLogN, logN - 1);
        //    }
        //}

        /* =================================================================== */

        /// <summary>
        /// Convert an integer polynomial (with small values) into the representation with complex numbers.
        /// </summary>
        private static void SmallIntsToFpr(FalconFpr[] rsrc, int r, sbyte[] tsrc, int t, int logN)
        {
            int n = 1 << logN;
            for (int u = 0; u < n; ++u)
            {
                rsrc[r + u] = FprEngine.FprOf(tsrc[t + u]);
            }
        }

        /*
        * The expanded private key contains:
        *  - The B0 matrix (four elements)
        *  - The ffLDL tree
        */
        //internal static int skoff_b00(int logN) => 0;

        //internal static int skoff_b01(int logN) => 1 << logN;

        //internal static int skoff_b10(int logN) => 2 * 1 << logN;

        //internal static int skoff_b11(int logN) => 3 * 1 << logN;

        //internal static int skoff_tree(int logN) => 4 * 1 << logN;

        /// <summary>Perform Fast Fourier Sampling for target vector t.</summary>
        /// <remarks>
        /// The Gram matrix is provided (G = [[g00, g01], [adj(g01), g11]]). The sampled vector is written over(t0, t1).
        /// The Gram matrix is modified as well. The tmp[] buffer must have room for four polynomials.
        /// </remarks>
        private static void FFSamplingFftDynTree(SamplerCtx samp_ctx, FalconFpr[] t0src, int t0, FalconFpr[] t1src,
            int t1, FalconFpr[] g00src, int g00, FalconFpr[] g01src, int g01, FalconFpr[] g11src, int g11, int origLogN,
            int logN, FalconFpr[] tmpsrc, int tmp)
        {
            /*
             * Deepest level: the LDL tree leaf value is just g00 (the array has length only 1 at this point); we
             * normalize it with regards to sigma, then use it for sampling.
             */
            if (logN == 0)
            {
                FalconFpr leaf = g00src[g00 + 0];
                leaf = FprEngine.FprMul(FprEngine.FprSqrt(leaf), FprEngine.FprInvSigma[origLogN]);
                t0src[t0 + 0] = FprEngine.FprOf(SamplerZ.Sample(samp_ctx, t0src[t0 + 0], leaf));
                t1src[t1 + 0] = FprEngine.FprOf(SamplerZ.Sample(samp_ctx, t1src[t1 + 0], leaf));
                return;
            }

            int n = 1 << logN;
            int hn = n >> 1;

            // Decompose G into LDL. We only need d00 (identical to g00), d11, and l10; we do that in place.
            FalconFft.PolyLdlFft(g00src, g00, g01src, g01, g11src, g11, logN);

            // Split d00 and d11 and expand them into half-size quasi-cyclic Gram matrices. We also save l10 in tmp[].
            FalconFft.PolySplitFft(tmpsrc, tmp, tmpsrc, tmp + hn, g00src, g00, logN);
            Array.Copy(tmpsrc, tmp, g00src, g00, n);
            FalconFft.PolySplitFft(tmpsrc, tmp, tmpsrc, tmp + hn, g11src, g11, logN);
            Array.Copy(tmpsrc, tmp, g11src, g11, n);
            Array.Copy(g01src, g01, tmpsrc, tmp, n);
            Array.Copy(g00src, g00,g01src, g01, hn);
            Array.Copy(g11src, g11, g01src, g01 + hn, hn);

            /*
             * The half-size Gram matrices for the recursive LDL tree building are now:
             *   - left sub-tree: g00, g00+hn, g01
             *   - right sub-tree: g11, g11+hn, g01+hn
             * l10 is in tmp[].
             */

            /*
             * We split t1 and use the first recursive call on the two halves, using the right sub-tree. The result is
             * merged back into tmp + 2*n.
             */
            int z1 = tmp + n;
            FalconFft.PolySplitFft(tmpsrc, z1, tmpsrc, z1 + hn, tmpsrc, t1, logN);
            FFSamplingFftDynTree(samp_ctx, tmpsrc, z1, tmpsrc, z1 + hn, g11src, g11, g11src, g11 + hn, g01src,
                g01 + hn, origLogN, logN - 1, tmpsrc, z1 + n);
            FalconFft.PolyMergeFft(tmpsrc, tmp + (n << 1), tmpsrc, z1, tmpsrc, z1 + hn, logN);

            /*
             * Compute tb0 = t0 + (t1 - z1) * l10.
             * At that point, l10 is in tmp, t1 is unmodified, and z1 is in tmp + (n << 1). The buffer in z1 is free.
             *
             * In the end, z1 is written over t1, and tb0 is in t0.
             */
            Array.Copy(tmpsrc, t1, tmpsrc, z1, n);
            FalconFft.PolySub(tmpsrc, z1, tmpsrc, tmp + (n << 1), logN);
            Array.Copy(tmpsrc, tmp + (n << 1), tmpsrc, t1, n);
            FalconFft.PolyMulFft(tmpsrc, tmp, tmpsrc, z1, logN);
            FalconFft.PolyAdd(tmpsrc, t0, tmpsrc, tmp, logN);

            // Second recursive invocation, on the split tb0 (currently in t0) and the left sub-tree.
            int z0 = tmp;
            FalconFft.PolySplitFft(tmpsrc, z0, tmpsrc, z0 + hn, tmpsrc, t0, logN);
            FFSamplingFftDynTree(samp_ctx, tmpsrc, z0, tmpsrc, z0 + hn, g00src, g00, g00src, g00 + hn, g01src, g01,
                origLogN, logN - 1, tmpsrc, z0 + n);
            FalconFft.PolyMergeFft(tmpsrc, t0, tmpsrc, z0, tmpsrc, z0 + hn, logN);
        }

        /*
        * Perform Fast Fourier Sampling for target vector t and LDL tree T.
        * tmp[] must have size for at least two polynomials of size 2^logn.
        */
        //internal static void ffSampling_fft(SamplerZ samp,
        //    FalconFPR[] z0src, int z0, FalconFPR[] z1src, int z1,
        //    FalconFPR[] treesrc, int tree,
        //    FalconFPR[] t0src, int t0, FalconFPR[] t1src, int t1, int logN,
        //    FalconFPR[] tmpsrc, int tmp)
        //{
        //    int tree0, tree1;

        //    /*
        //    * When logN == 2, we inline the last two recursion levels.
        //    */
        //    if (logN == 2)
        //    {
        //        FalconFPR x0, x1, y0, y1, w0, w1, w2, w3, sigma;
        //        FalconFPR a_re, a_im, b_re, b_im, c_re, c_im;

        //        tree0 = tree + 4;
        //        tree1 = tree + 8;

        //        /*
        //        * We split t1 into w*, then do the recursive invocation,
        //        * with output in w*. We finally merge back into z1.
        //        */
        //        a_re = t1src[t1+0];
        //        a_im = t1src[t1 + 2];
        //        b_re = t1src[t1 + 1];
        //        b_im = t1src[t1 + 3];
        //        c_re = FprEngine.fpr_add(a_re, b_re);
        //        c_im = FprEngine.fpr_add(a_im, b_im);
        //        w0 = FprEngine.fpr_half(c_re);
        //        w1 = FprEngine.fpr_half(c_im);
        //        c_re = FprEngine.fpr_sub(a_re, b_re);
        //        c_im = FprEngine.fpr_sub(a_im, b_im);
        //        w2 = FprEngine.fpr_mul(FprEngine.fpr_add(c_re, c_im), FprEngine.fpr_invsqrt8);
        //        w3 = FprEngine.fpr_mul(FprEngine.fpr_sub(c_im, c_re), FprEngine.fpr_invsqrt8);

        //        x0 = w2;
        //        x1 = w3;
        //        sigma = treesrc[tree1 + 3];
        //        w2 = FprEngine.fpr_of(samp.Sample(x0, sigma));
        //        w3 = FprEngine.fpr_of(samp.Sample(x1, sigma));
        //        a_re = FprEngine.fpr_sub(x0, w2);
        //        a_im = FprEngine.fpr_sub(x1, w3);
        //        b_re = treesrc[tree1 + 0];
        //        b_im = treesrc[tree1 + 1];
        //        c_re = FprEngine.fpr_sub(FprEngine.fpr_mul(a_re, b_re), FprEngine.fpr_mul(a_im, b_im));
        //        c_im = FprEngine.fpr_add(FprEngine.fpr_mul(a_re, b_im), FprEngine.fpr_mul(a_im, b_re));
        //        x0 = FprEngine.fpr_add(c_re, w0);
        //        x1 = FprEngine.fpr_add(c_im, w1);
        //        sigma = treesrc[tree1 + 2];
        //        w0 = FprEngine.fpr_of(samp.Sample(x0, sigma));
        //        w1 = FprEngine.fpr_of(samp.Sample(x1, sigma));

        //        a_re = w0;
        //        a_im = w1;
        //        b_re = w2;
        //        b_im = w3;
        //        c_re = FprEngine.fpr_mul(FprEngine.fpr_sub(b_re, b_im), FprEngine.fpr_invsqrt2);
        //        c_im = FprEngine.fpr_mul(FprEngine.fpr_add(b_re, b_im), FprEngine.fpr_invsqrt2);
        //        z1src[z1 + 0] = w0 = FprEngine.fpr_add(a_re, c_re);
        //        z1src[z1 + 2] = w2 = FprEngine.fpr_add(a_im, c_im);
        //        z1src[z1 + 1] = w1 = FprEngine.fpr_sub(a_re, c_re);
        //        z1src[z1 + 3] = w3 = FprEngine.fpr_sub(a_im, c_im);

        //        /*
        //        * Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in w*.
        //        */
        //        w0 = FprEngine.fpr_sub(t1src[t1+0], w0);
        //        w1 = FprEngine.fpr_sub(t1src[t1 + 1], w1);
        //        w2 = FprEngine.fpr_sub(t1src[t1 + 2], w2);
        //        w3 = FprEngine.fpr_sub(t1src[t1 + 3], w3);

        //        a_re = w0;
        //        a_im = w2;
        //        b_re = treesrc[tree+0];
        //        b_im = treesrc[tree + 2];
        //        w0 = FprEngine.fpr_sub(FprEngine.fpr_mul(a_re, b_re), FprEngine.fpr_mul(a_im, b_im));
        //        w2 = FprEngine.fpr_add(FprEngine.fpr_mul(a_re, b_im), FprEngine.fpr_mul(a_im, b_re));
        //        a_re = w1;
        //        a_im = w3;
        //        b_re = treesrc[tree + 1];
        //        b_im = treesrc[tree + 3];
        //        w1 = FprEngine.fpr_sub(FprEngine.fpr_mul(a_re, b_re), FprEngine.fpr_mul(a_im, b_im));
        //        w3 = FprEngine.fpr_add(FprEngine.fpr_mul(a_re, b_im), FprEngine.fpr_mul(a_im, b_re));

        //        w0 = FprEngine.fpr_add(w0, t0src[t0+0]);
        //        w1 = FprEngine.fpr_add(w1, t0src[t0 + 1]);
        //        w2 = FprEngine.fpr_add(w2, t0src[t0 + 2]);
        //        w3 = FprEngine.fpr_add(w3, t0src[t0 + 3]);

        //        /*
        //        * Second recursive invocation.
        //        */
        //        a_re = w0;
        //        a_im = w2;
        //        b_re = w1;
        //        b_im = w3;
        //        c_re = FprEngine.fpr_add(a_re, b_re);
        //        c_im = FprEngine.fpr_add(a_im, b_im);
        //        w0 = FprEngine.fpr_half(c_re);
        //        w1 = FprEngine.fpr_half(c_im);
        //        c_re = FprEngine.fpr_sub(a_re, b_re);
        //        c_im = FprEngine.fpr_sub(a_im, b_im);
        //        w2 = FprEngine.fpr_mul(FprEngine.fpr_add(c_re, c_im), FprEngine.fpr_invsqrt8);
        //        w3 = FprEngine.fpr_mul(FprEngine.fpr_sub(c_im, c_re), FprEngine.fpr_invsqrt8);

        //        x0 = w2;
        //        x1 = w3;
        //        sigma = treesrc[tree0 + 3];
        //        w2 = y0 = FprEngine.fpr_of(samp.Sample(x0, sigma));
        //        w3 = y1 = FprEngine.fpr_of(samp.Sample(x1, sigma));
        //        a_re = FprEngine.fpr_sub(x0, y0);
        //        a_im = FprEngine.fpr_sub(x1, y1);
        //        b_re = treesrc[tree0 + 0];
        //        b_im = treesrc[tree0 + 1];
        //        c_re = FprEngine.fpr_sub(FprEngine.fpr_mul(a_re, b_re), FprEngine.fpr_mul(a_im, b_im));
        //        c_im = FprEngine.fpr_add(FprEngine.fpr_mul(a_re, b_im), FprEngine.fpr_mul(a_im, b_re));
        //        x0 = FprEngine.fpr_add(c_re, w0);
        //        x1 = FprEngine.fpr_add(c_im, w1);
        //        sigma = treesrc[tree0 + 2];
        //        w0 = FprEngine.fpr_of(samp.Sample(x0, sigma));
        //        w1 = FprEngine.fpr_of(samp.Sample(x1, sigma));

        //        a_re = w0;
        //        a_im = w1;
        //        b_re = w2;
        //        b_im = w3;
        //        c_re = FprEngine.fpr_mul(FprEngine.fpr_sub(b_re, b_im), FprEngine.fpr_invsqrt2);
        //        c_im = FprEngine.fpr_mul(FprEngine.fpr_add(b_re, b_im), FprEngine.fpr_invsqrt2);
        //        z0src[z0 + 0] = FprEngine.fpr_add(a_re, c_re);
        //        z0src[z0 + 2] = FprEngine.fpr_add(a_im, c_im);
        //        z0src[z0 + 1] = FprEngine.fpr_sub(a_re, c_re);
        //        z0src[z0 + 3] = FprEngine.fpr_sub(a_im, c_im);

        //        return;
        //    }

        //    /*
        //    * Case logN == 1 is reachable only when using Falcon-2 (the
        //    * smallest size for which Falcon is mathematically defined, but
        //    * of course way too insecure to be of any use).
        //    */
        //    if (logN == 1)
        //    {
        //        FalconFPR x0, x1, y0, y1, sigma;
        //        FalconFPR a_re, a_im, b_re, b_im, c_re, c_im;

        //        x0 = t1src[t1+0];
        //        x1 = t1src[t1 + 1];
        //        sigma = treesrc[tree + 3];
        //        z1src[z1 + 0] = y0 = FprEngine.fpr_of(samp.Sample(x0, sigma));
        //        z1src[z1 + 1] = y1 = FprEngine.fpr_of(samp.Sample(x1, sigma));
        //        a_re = FprEngine.fpr_sub(x0, y0);
        //        a_im = FprEngine.fpr_sub(x1, y1);
        //        b_re = treesrc[tree+0];
        //        b_im = treesrc[tree + 1];
        //        c_re = FprEngine.fpr_sub(FprEngine.fpr_mul(a_re, b_re), FprEngine.fpr_mul(a_im, b_im));
        //        c_im = FprEngine.fpr_add(FprEngine.fpr_mul(a_re, b_im), FprEngine.fpr_mul(a_im, b_re));
        //        x0 = FprEngine.fpr_add(c_re, t0src[t0+0]);
        //        x1 = FprEngine.fpr_add(c_im, t0src[t0 + 1]);
        //        sigma = treesrc[tree + 2];
        //        z0src[z0 + 0] = FprEngine.fpr_of(samp.Sample(x0, sigma));
        //        z0src[z0 + 1] = FprEngine.fpr_of(samp.Sample(x1, sigma));

        //        return;
        //    }

        //    /*
        //    * Normal end of recursion is for logN == 0. Since the last
        //    * steps of the recursions were inlined in the blocks above
        //    * (when logN == 1 or 2), this case is not reachable, and is
        //    * retained here only for documentation purposes.

        //    if (logN == 0) {
        //        fpr x0, x1, sigma;

        //        x0 = t0src[t0+0];
        //        x1 = t1src[t1+0];
        //        sigma = treesrc[tree+0];
        //        z0[0] = FprEngine.fpr_of(samp.sample(x0, sigma));
        //        z1src[z1 + 0] = FprEngine.fpr_of(samp.sample(x1, sigma));
        //        return;
        //    }

        //    */

        //    /*
        //    * General recursive case (logN >= 3).
        //    */

        //    int n = 1 << logN;
        //    int hn = n >> 1;
        //    tree0 = tree + n;
        //    tree1 = tree + n + (int)ffLDL_treesize(logN - 1);

        //    /*
        //    * We split t1 into z1 (reused as temporary storage), then do
        //    * the recursive invocation, with output in tmp. We finally
        //    * merge back into z1.
        //    */
        //    this.ffte.poly_split_fft(z1src, z1, z1src, z1 + hn, t1src, t1, logN);
        //    ffSampling_fft(samp, tmpsrc, tmp, tmpsrc, tmp + hn,
        //        treesrc, tree1, z1src, z1, z1src, z1 + hn, logN - 1, tmpsrc, tmp + n);
        //    this.ffte.poly_merge_fft(z1src, z1, tmpsrc, tmp, tmpsrc, tmp + hn, logN);

        //    /*
        //    * Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in tmp[].
        //    */
        //    Array.Copy(t1src, t1, tmpsrc, tmp, n);
        //    this.ffte.poly_sub(tmpsrc, tmp, z1src, z1, logN);
        //    this.ffte.poly_mul_fft(tmpsrc, tmp, treesrc, tree, logN);
        //    this.ffte.poly_add(tmpsrc, tmp, t0src, t0, logN);

        //    /*
        //    * Second recursive invocation.
        //    */
        //    this.ffte.poly_split_fft(z0src, z0, z0src, z0 + hn, tmpsrc, tmp, logN);
        //    ffSampling_fft(samp, tmpsrc, tmp, tmpsrc, tmp + hn,
        //        treesrc, tree0, z0src, z0, z0src, z0 + hn, logN - 1, tmpsrc, tmp + n);
        //    this.ffte.poly_merge_fft(z0src, z0, tmpsrc, tmp, tmpsrc, tmp + hn, logN);
        //}

        /*
        * Compute a signature: the signature contains two vectors, s1 and s2.
        * The s1 vector is not returned. The squared norm of (s1,s2) is
        * computed, and if it is short enough, then s2 is returned into the
        * s2[] buffer, and 1 is returned; otherwise, s2[] is untouched and 0 is
        * returned; the caller should then try again. This function uses an
        * expanded key.
        *
        * tmp[] must have room for at least six polynomials.
        */
        //internal static int do_sign_tree(SamplerZ samp, short[] s2src, int s2, FalconFPR[] ex_keysrc, int expanded_key,
        //    ushort[] hmsrc, int hm, int logN, FalconFPR[] tmpsrc, int tmp)
        //{
        //    int n = 1 << logN;
        //    int t0 = tmp;
        //    int t1 = t0 + n;
        //    int b00 = expanded_key + skoff_b00(logN);
        //    int b01 = expanded_key + skoff_b01(logN);
        //    int b10 = expanded_key + skoff_b10(logN);
        //    int b11 = expanded_key + skoff_b11(logN);
        //    int tree = expanded_key + skoff_tree(logN);

        //    /*
        //    * Set the target vector to [hm, 0] (hm is the hashed message).
        //    */
        //    for (int u = 0; u < n; ++u)
        //    {
        //        tmpsrc[t0 + u] = FprEngine.fpr_of(hmsrc[hm + u]);
        //        /* This is implicit.
        //        t1src[t1 + u] = fpr_zero;
        //        */
        //    }

        //    /*
        //    * Apply the lattice basis to obtain the real target
        //    * vector (after normalization with regards to modulus).
        //    */
        //    this.ffte.FFT(tmpsrc, t0, logN);
        //    FalconFPR ni = FprEngine.fpr_inverse_of_q;
        //    Array.Copy(tmpsrc, t0, tmpsrc, t1, n);
        //    this.ffte.poly_mul_fft(tmpsrc, t1, ex_keysrc, b01, logN);
        //    this.ffte.poly_mulconst(tmpsrc, t1, FprEngine.fpr_neg(ni), logN);
        //    this.ffte.poly_mul_fft(tmpsrc, t0, ex_keysrc, b11, logN);
        //    this.ffte.poly_mulconst(tmpsrc, t0, ni, logN);

        //    int tx = t1 + n;
        //    int ty = tx + n;

        //    /*
        //    * Apply sampling. Output is written back in [tx, ty].
        //    */
        //    ffSampling_fft(samp, tmpsrc, tx, tmpsrc, ty, ex_keysrc, tree, tmpsrc, t0, tmpsrc, t1, logN, tmpsrc,
        //        ty + n);

        //    /*
        //    * Get the lattice point corresponding to that tiny vector.
        //    */
        //    Array.Copy(tmpsrc, tx, tmpsrc, t0, n);
        //    Array.Copy(tmpsrc, ty, tmpsrc, t1, n);
        //    this.ffte.poly_mul_fft(tmpsrc, tx, ex_keysrc, b00, logN);
        //    this.ffte.poly_mul_fft(tmpsrc, ty, ex_keysrc, b10, logN);
        //    this.ffte.poly_add(tmpsrc, tx, tmpsrc, ty, logN);
        //    Array.Copy(tmpsrc, t0, tmpsrc, ty, n);
        //    this.ffte.poly_mul_fft(tmpsrc, ty, ex_keysrc, b01, logN);

        //    Array.Copy(tmpsrc, tx, tmpsrc, t0, n);
        //    this.ffte.poly_mul_fft(tmpsrc, t1, ex_keysrc, b11, logN);
        //    this.ffte.poly_add(tmpsrc, t1, tmpsrc, ty, logN);

        //    this.ffte.iFFT(tmpsrc, t0, logN);
        //    this.ffte.iFFT(tmpsrc, t1, logN);

        //    /*
        //    * Compute the signature.
        //    */
        //    short[] s1tmp = new short[n];
        //    short[] s2tmp = new short[n];
        //    uint sqn = 0;
        //    uint ng = 0;
        //    for (int u = 0; u < n; ++u)
        //    {
        //        int z = (int)hmsrc[hm + u] - (int)FprEngine.fpr_rint(tmpsrc[t0 + u]);
        //        sqn += (uint)(z * z);
        //        ng |= sqn;
        //        s1tmp[u] = (short)z;
        //    }
        //    sqn |= (uint)(-(ng >> 31));

        //    /*
        //    * With "normal" degrees (e.g. 512 or 1024), it is very
        //    * improbable that the computed vector is not short enough;
        //    * however, it may happen in practice for the very reduced
        //    * versions (e.g. degree 16 or below). In that case, the caller
        //    * will loop, and we must not write anything into s2[] because
        //    * s2[] may overlap with the hashed message hm[] and we need
        //    * hm[] for the next iteration.
        //    */
        //    for (int u = 0; u < n; ++u)
        //    {
        //        s2tmp[u] = (short)-FprEngine.fpr_rint(tmpsrc[t1 + u]);
        //    }
        //    if (FalconCommon.is_short_half(sqn, s2tmp, 0, logN))
        //    {
        //        Array.Copy(s2tmp, 0, s2src, s2, n);
        //        Array.Copy(s1tmp, 0, tmpsrc, tmp, n);
        //        return 1;
        //    }
        //    return 0;
        //}

        /// <summary>Compute a signature: the signature contains two vectors, s1 and s2.</summary>
        /// <remarks>
        /// The s1 vector is not returned. The squared norm of (s1, s2) is computed, and if it is short enough, then s2
        /// is returned into the s2[] buffer, and 1 is returned; otherwise, s2[] is untouched and 0 is returned; the
        /// caller should then try again. tmp[] must have room for at least nine polynomials.
        /// </remarks>
        private static int DoSignDyn(SamplerCtx samp_ctx, short[] s2src, int s2, sbyte[] fsrc, int f, sbyte[] gsrc,
            int g, sbyte[] Fsrc, int F, sbyte[] Gsrc, int G, ushort[] hmsrc, int hm, int logN, FalconFpr[] tmpsrc,
            int tmp)
        {
            int u;
            int n = 1 << logN;

            // Lattice basis is B = [[g, -f], [G, -F]]. We convert it to FFT.
            int b00 = tmp;
            int b01 = b00 + n;
            int b10 = b01 + n;
            int b11 = b10 + n;
            SmallIntsToFpr(tmpsrc, b01, fsrc, f, logN);
            SmallIntsToFpr(tmpsrc, b00, gsrc, g, logN);
            SmallIntsToFpr(tmpsrc, b11, Fsrc, F, logN);
            SmallIntsToFpr(tmpsrc, b10, Gsrc, G, logN);
            FalconFft.Fft(tmpsrc, b01, logN);
            FalconFft.Fft(tmpsrc, b00, logN);
            FalconFft.Fft(tmpsrc, b11, logN);
            FalconFft.Fft(tmpsrc, b10, logN);
            FalconFft.PolyNeg(tmpsrc, b01, logN);
            FalconFft.PolyNeg(tmpsrc, b11, logN);

            /*
             * Compute the Gram matrix G = B·B*. Formulas are:
             *   g00 = b00*adj(b00) + b01*adj(b01)
             *   g01 = b00*adj(b10) + b01*adj(b11)
             *   g10 = b10*adj(b00) + b11*adj(b01)
             *   g11 = b10*adj(b10) + b11*adj(b11)
             *
             * For historical reasons, this implementation uses g00, g01 and g11 (upper triangle). g10 is not kept since
             * it is equal to adj(g01). We _replace_ the matrix B with the Gram matrix, but we must keep b01 and b11 for
             * computing the target vector.
             */
            int t0 = b11 + n;
            int t1 = t0 + n;

            Array.Copy(tmpsrc, b01, tmpsrc, t0, n);
            FalconFft.PolyMulSelfAdjFft(tmpsrc, t0, logN);              // t0 <- b01*adj(b01)

            Array.Copy(tmpsrc, b00, tmpsrc, t1, n);
            FalconFft.PolyMulAdjFft(tmpsrc, t1, tmpsrc, b10, logN);     // t1 <- b00*adj(b10)
            FalconFft.PolyMulSelfAdjFft(tmpsrc, b00, logN);             // b00 <- b00*adj(b00)
            FalconFft.PolyAdd(tmpsrc, b00, tmpsrc, t0, logN);           // b00 <- g00
            Array.Copy(tmpsrc, b01, tmpsrc, t0, n);
            FalconFft.PolyMulAdjFft(tmpsrc, b01, tmpsrc, b11, logN);    // b01 <- b01*adj(b11)
            FalconFft.PolyAdd(tmpsrc, b01, tmpsrc, t1, logN);           // b01 <- g01

            FalconFft.PolyMulSelfAdjFft(tmpsrc, b10, logN);             // b10 <- b10*adj(b10)
            Array.Copy(tmpsrc, b11, tmpsrc, t1, n);
            FalconFft.PolyMulSelfAdjFft(tmpsrc, t1, logN);              // t1 <- b11*adj(b11)
            FalconFft.PolyAdd(tmpsrc, b10, tmpsrc, t1, logN);           // b10 <- g11

            /*
             * We rename variables to make things clearer. The three elements of the Gram matrix uses the first 3*n
             * slots of tmp[], followed by b11 and b01 (in that order).
             */
            int g00 = b00;
            int g01 = b01;
            int g11 = b10;
            b01 = t0;
            t0 = b01 + n;
            t1 = t0 + n;

            // Memory layout at this point: g00 g01 g11 b11 b01 t0 t1

            // Set the target vector to [hm, 0] (hm is the hashed message).
            for (u = 0; u < n; ++u)
            {
                tmpsrc[t0 + u] = FprEngine.FprOf((short)hmsrc[hm + u]);
                /* This is implicit.
                t1src[t1 + u] = FprEngine.fpr_zero;
                */
            }

            // Apply the lattice basis to obtain the real target vector (after normalization with regards to modulus).
            FalconFft.Fft(tmpsrc, t0, logN);
            FalconFpr ni = FprEngine.FprInvQ;
            Array.Copy(tmpsrc, t0, tmpsrc, t1, n);
            FalconFft.PolyMulFft(tmpsrc, t1, tmpsrc, b01, logN);
            FalconFft.PolyMulConst(tmpsrc, t1, FprEngine.FprNeg(ni), logN);
            FalconFft.PolyMulFft(tmpsrc, t0, tmpsrc, b11, logN);
            FalconFft.PolyMulConst(tmpsrc, t0, ni, logN);

            /*
             * b01 and b11 can be discarded, so we move back (t0,t1).
             * Memory layout is now: g00 g01 g11 t0 t1
             */
            Array.Copy(tmpsrc, t0, tmpsrc, b11, n * 2);
            t0 = g11 + n;
            t1 = t0 + n;

            // Apply sampling; result is written over (t0,t1).
            FFSamplingFftDynTree(samp_ctx, tmpsrc, t0, tmpsrc, t1, tmpsrc, g00, tmpsrc, g01, tmpsrc, g11, logN, logN,
                tmpsrc, t1 + n);

            /*
             * We arrange the layout back to: b00 b01 b10 b11 t0 t1
             *
             * We did not conserve the matrix basis, so we must recompute it now.
             */
            b00 = tmp;
            b01 = b00 + n;
            b10 = b01 + n;
            b11 = b10 + n;
            Array.Copy(tmpsrc, t0, tmpsrc, b11 + n, n * 2);
            t0 = b11 + n;
            t1 = t0 + n;
            SmallIntsToFpr(tmpsrc, b01, fsrc, f, logN);
            SmallIntsToFpr(tmpsrc, b00, gsrc, g, logN);
            SmallIntsToFpr(tmpsrc, b11, Fsrc, F, logN);
            SmallIntsToFpr(tmpsrc, b10, Gsrc, G, logN);
            FalconFft.Fft(tmpsrc, b01, logN);
            FalconFft.Fft(tmpsrc, b00, logN);
            FalconFft.Fft(tmpsrc, b11, logN);
            FalconFft.Fft(tmpsrc, b10, logN);
            FalconFft.PolyNeg(tmpsrc, b01, logN);
            FalconFft.PolyNeg(tmpsrc, b11, logN);
            int tx = t1 + n;
            int ty = tx + n;

            // Get the lattice point corresponding to that tiny vector.
            Array.Copy(tmpsrc, t0, tmpsrc, tx, n);
            Array.Copy(tmpsrc, t1, tmpsrc, ty, n);
            FalconFft.PolyMulFft(tmpsrc, tx, tmpsrc, b00, logN);
            FalconFft.PolyMulFft(tmpsrc, ty, tmpsrc, b10, logN);
            FalconFft.PolyAdd(tmpsrc, tx, tmpsrc, ty, logN);
            Array.Copy(tmpsrc, t0, tmpsrc, ty, n);
            FalconFft.PolyMulFft(tmpsrc, ty, tmpsrc, b01, logN);

            Array.Copy(tmpsrc, tx, tmpsrc, t0, n);
            FalconFft.PolyMulFft(tmpsrc, t1, tmpsrc, b11, logN);
            FalconFft.PolyAdd(tmpsrc, t1, tmpsrc, ty, logN);
            FalconFft.InvFft(tmpsrc, t0, logN);
            FalconFft.InvFft(tmpsrc, t1, logN);

            short[] s1tmp = new short[n];
            uint sqn = 0;
            uint ng = 0;
            for (u = 0; u < n; ++u)
            {
                int z = (int)hmsrc[hm + u] - (int)FprEngine.FprRInt(tmpsrc[t0 + u]);
                sqn += (uint)(z * z);
                ng |= sqn;
                s1tmp[u] = (short)z;
            }
            sqn |= (uint)(-(ng >> 31));

            /*
             * With "normal" degrees (e.g. 512 or 1024), it is very improbable that the computed vector is not short
             * enough; however, it may happen in practice for the very reduced versions (e.g. degree 16 or below). In
             * that case, the caller will loop, and we must not write anything into s2[] because s2[] may overlap with
             * the hashed message hm[] and we need hm[] for the next iteration.
             */
            short[] s2tmp = new short[n];
            for (u = 0; u < n; ++u)
            {
                s2tmp[u] = (short)-FprEngine.FprRInt(tmpsrc[t1 + u]);
            }
            if (FalconCommon.IsShortHalf(sqn, s2tmp, 0, logN))
            {
                Array.Copy(s2tmp, 0, s2src, s2, n);
                //Array.Copy(s1tmp, 0, tmpsrc, tmp, n);
                return 1;
            }
            return 0;
        }

        //internal static void sign_tree(short[] sigsrc, int sig, SHAKE256 rng, FalconFPR[] ex_keysrc, int expanded_key,
        //    ushort[] hmsrc, int hm, int logN, FalconFPR[] tmpsrc, int tmp)
        //{
        //    int ftmp = tmp;
        //    for (;;)
        //    {
        //        /*
        //        * Signature produces short vectors s1 and s2. The
        //        * signature is acceptable only if the aggregate vector
        //        * s1,s2 is short; we must use the same bound as the
        //        * verifier.
        //        *
        //        * If the signature is acceptable, then we return only s2
        //        * (the verifier recomputes s1 from s2, the hashed message,
        //        * and the public key).
        //        */

        //        /*
        //        * Normal sampling. We use a fast PRNG seeded from our
        //        * SHAKE context ('rng').
        //        */
        //        FalconRNG prng = new FalconRNG();
        //        prng.prng_init(rng);
        //        SamplerZ samp = new SamplerZ(prng, FprEngine.fpr_sigma_min[logN], FprEngine);

        //        /*
        //        * Do the actual signature.
        //        */
        //        if (do_sign_tree(samp, sigsrc, sig, ex_keysrc, expanded_key, hmsrc, hm, logN, tmpsrc, ftmp) != 0)
        //            break;
        //    }
        //}

        internal static void SignDyn(short[] sigsrc, int sig, ShakeDigest rng, sbyte[] fsrc, int f, sbyte[] gsrc, int g,
            sbyte[] Fsrc, int F, sbyte[] Gsrc, int G, ushort[] hmsrc, int hm, int logN, FalconFpr[] tmpsrc, int tmp)
        {
            SamplerCtx samp_ctx = new SamplerCtx(FprEngine.FprSigmaMin[logN]);
            try
            {
                for (;;)
                {
                    /*
                    * Normal sampling. We use a fast PRNG seeded from our SHAKE context ('rng').
                    */
                    samp_ctx.p.Init(rng);

                    /*
                    * Signature produces short vectors s1 and s2. The signature is acceptable only if the aggregate
                    * vector s1,s2 is short; we must use the same bound as the verifier.
                    *
                    * If the signature is acceptable, then we return only s2 (the verifier recomputes s1 from s2, the
                    * hashed message, and the public key).
                    */
                    int result = DoSignDyn(samp_ctx, sigsrc, sig, fsrc, f, gsrc, g, Fsrc, F, Gsrc, G, hmsrc, hm,
                        logN, tmpsrc, tmp);

                    if (result != 0)
                        break;
                }
            }
            finally
            {
                samp_ctx.p.Clear();
            }
        }
    }
}
