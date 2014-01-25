using System;

using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.Field;

namespace Org.BouncyCastle.Math.EC
{
    public class ECAlgorithms
    {
        public static bool IsF2mCurve(ECCurve c)
        {
            IFiniteField field = c.Field;
            return field.Dimension > 1 && field.Characteristic.Equals(BigInteger.Two)
                && field is IPolynomialExtensionField;
        }

        public static bool IsFpCurve(ECCurve c)
        {
            return c.Field.Dimension == 1;
        }

        public static ECPoint SumOfTwoMultiplies(ECPoint P, BigInteger a, ECPoint Q, BigInteger b)
        {
            ECCurve cp = P.Curve;
            Q = ImportPoint(cp, Q);

            // Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick
            if (cp is F2mCurve)
            {
                F2mCurve f2mCurve = (F2mCurve) cp;
                if (f2mCurve.IsKoblitz)
                {
                    return P.Multiply(a).Add(Q.Multiply(b));
                }
            }

            return ImplShamirsTrick(P, a, Q, b);
        }

        /*
        * "Shamir's Trick", originally due to E. G. Straus
        * (Addition chains of vectors. American Mathematical Monthly,
        * 71(7):806-808, Aug./Sept. 1964)
        *  
        * Input: The points P, Q, scalar k = (km?, ... , k1, k0)
        * and scalar l = (lm?, ... , l1, l0).
        * Output: R = k * P + l * Q.
        * 1: Z <- P + Q
        * 2: R <- O
        * 3: for i from m-1 down to 0 do
        * 4:        R <- R + R        {point doubling}
        * 5:        if (ki = 1) and (li = 0) then R <- R + P end if
        * 6:        if (ki = 0) and (li = 1) then R <- R + Q end if
        * 7:        if (ki = 1) and (li = 1) then R <- R + Z end if
        * 8: end for
        * 9: return R
        */
        public static ECPoint ShamirsTrick(ECPoint P, BigInteger k, ECPoint Q, BigInteger l)
        {
            ECCurve cp = P.Curve;
            Q = ImportPoint(cp, Q);

            return ImplShamirsTrick(P, k, Q, l);
        }

        public static ECPoint ImportPoint(ECCurve c, ECPoint p)
        {
            ECCurve cp = p.Curve;
            if (!c.Equals(cp))
                throw new ArgumentException("Point must be on the same curve");

            return c.ImportPoint(p);
        }

        public static void MontgomeryTrick(ECFieldElement[] zs, int off, int len)
        {
            /*
             * Uses the "Montgomery Trick" to invert many field elements, with only a single actual
             * field inversion. See e.g. the paper:
             * "Fast Multi-scalar Multiplication Methods on Elliptic Curves with Precomputation Strategy Using Montgomery Trick"
             * by Katsuyuki Okeya, Kouichi Sakurai.
             */

            ECFieldElement[] c = new ECFieldElement[len];
            c[0] = zs[off];

            int i = 0;
            while (++i < len)
            {
                c[i] = c[i - 1].Multiply(zs[off + i]);
            }

            ECFieldElement u = c[--i].Invert();

            while (i > 0)
            {
                int j = off + i--;
                ECFieldElement tmp = zs[j];
                zs[j] = c[i].Multiply(u);
                u = u.Multiply(tmp);
            }

            zs[off] = u;
        }

        internal static ECPoint ImplShamirsTrick(ECPoint P, BigInteger k,
            ECPoint Q, BigInteger l)
        {
            ECCurve curve = P.Curve;
            ECPoint infinity = curve.Infinity;

            // TODO conjugate co-Z addition (ZADDC) can return both of these
            ECPoint PaddQ = P.Add(Q);
            ECPoint PsubQ = P.Subtract(Q);

            ECPoint[] points = new ECPoint[] { Q, PsubQ, P, PaddQ };
            curve.NormalizeAll(points);

            ECPoint[] table = new ECPoint[] {
            points[3].Negate(), points[2].Negate(), points[1].Negate(),
            points[0].Negate(), infinity, points[0],
            points[1], points[2], points[3] };

            byte[] jsf = WNafUtilities.GenerateJsf(k, l);

            ECPoint R = infinity;

            int i = jsf.Length;
            while (--i >= 0)
            {
                int jsfi = jsf[i];

                // NOTE: The shifting ensures the sign is extended correctly
                int kDigit = ((jsfi << 24) >> 28), lDigit = ((jsfi << 28) >> 28);

                int index = 4 + (kDigit * 3) + lDigit;
                R = R.TwicePlus(table[index]);
            }

            return R;
        }
    }
}
