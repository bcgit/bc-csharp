using System.Runtime.CompilerServices;

namespace Org.BouncyCastle.Pqc.Crypto.Falcon
{
    /// <summary>
    /// A complex number in Falcon's floating-point (FPR) domain: the FPC_* macro family from the reference fft.c.
    /// </summary>
    /// <remarks>
    /// This is a transient compute value only. The FFT array representation keeps real and imaginary parts in
    /// separate array halves; values are packed into a <see cref="FalconFpc"/> for arithmetic and unpacked again
    /// for storage. The fields are raw doubles rather than <see cref="FalconFpr"/> because (as of .NET 6) RyuJIT
    /// does not fully promote structs whose fields are themselves structs, which costs more than the packaging
    /// saves. The arithmetic below is exactly the FprEngine operations on the underlying doubles.
    /// </remarks>
    internal readonly struct FalconFpc
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

        private readonly double re, im;

        internal FalconFpr Re => new FalconFpr(re);

        internal FalconFpr Im => new FalconFpr(im);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal FalconFpc(FalconFpr re, FalconFpr im)
        {
            this.re = re.v;
            this.im = im.v;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private FalconFpc(double re, double im)
        {
            this.re = re;
            this.im = im;
        }

        /// <summary>Addition of two complex numbers (d = a + b).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Add(FalconFpc a, FalconFpc b) => new FalconFpc(a.re + b.re, a.im + b.im);

        /// <summary>Subtraction of two complex numbers (d = a - b).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Sub(FalconFpc a, FalconFpc b) => new FalconFpc(a.re - b.re, a.im - b.im);

        /// <summary>Multiplication of two complex numbers (d = a * b).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Mul(FalconFpc a, FalconFpc b) =>
            new FalconFpc(a.re * b.re - a.im * b.im, a.re * b.im + a.im * b.re);

        /// <summary>Squaring of a complex number (d = a * a).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Sqr(FalconFpc a) => Mul(a, a);

        /// <summary>Inversion of a complex number (d = 1 / a).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Inv(FalconFpc a)
        {
            double m = 1.0 / (a.re * a.re + a.im * a.im);
            return new FalconFpc(a.re * m, -a.im * m);
        }

        /// <summary>Division of complex numbers (d = a / b).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Div(FalconFpc a, FalconFpc b) => Mul(a, Inv(b));

        /// <summary>Conjugation of a complex number (d = conj(a)).</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static FalconFpc Conj(FalconFpc a) => new FalconFpc(a.re, -a.im);
    }
}
