using System;

using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Abc
{
    /**
    * Class holding methods for point multiplication based on the window
    * &#964;-adic nonadjacent form (WTNAF). The algorithms are based on the
    * paper "Improved Algorithms for Arithmetic on Anomalous Binary Curves"
    * by Jerome A. Solinas. The paper first appeared in the Proceedings of
    * Crypto 1997.
    */
    internal static class Tnaf
    {
        private static readonly BigInteger MinusOne = BigInteger.One.Negate();
        private static readonly BigInteger MinusTwo = BigInteger.Two.Negate();
        private static readonly BigInteger MinusThree = BigInteger.Three.Negate();
        private static readonly BigInteger Four = BigInteger.ValueOf(4);

        private static readonly string PRECOMP_NAME = "bc_tnaf_partmod";

        /**
        * The window width of WTNAF. The standard value of 4 is slightly less
        * than optimal for running time, but keeps space requirements for
        * precomputation low. For typical curves, a value of 5 or 6 results in
        * a better running time. When changing this value, the
        * <code>&#945;<sub>u</sub></code>'s must be computed differently, see
        * e.g. "Guide to Elliptic Curve Cryptography", Darrel Hankerson,
        * Alfred Menezes, Scott Vanstone, Springer-Verlag New York Inc., 2004,
        * p. 121-122
        */
        public const sbyte Width = 4;

        /**
        * The <code>&#945;<sub>u</sub></code>'s for <code>a=0</code> as an array
        * of <code>ZTauElement</code>s.
        */
        public static readonly ZTauElement[] Alpha0 =
        {
            null, new ZTauElement(BigInteger.One, BigInteger.Zero),
            null, new ZTauElement(MinusThree, MinusOne),
            null, new ZTauElement(MinusOne, MinusOne),
            null, new ZTauElement(BigInteger.One, MinusOne),
            null, new ZTauElement(MinusOne, BigInteger.One),
            null, new ZTauElement(BigInteger.One, BigInteger.One),
            null, new ZTauElement(BigInteger.Three, BigInteger.One),
            null, new ZTauElement(MinusOne, BigInteger.Zero),
        };

        /**
        * The <code>&#945;<sub>u</sub></code>'s for <code>a=0</code> as an array
        * of TNAFs.
        */
        public static readonly sbyte[][] Alpha0Tnaf =
        {
            null, new sbyte[]{1}, null, new sbyte[]{-1, 0, 1}, null, new sbyte[]{1, 0, 1}, null, new sbyte[]{-1, 0, 0, 1}
        };

        /**
        * The <code>&#945;<sub>u</sub></code>'s for <code>a=1</code> as an array
        * of <code>ZTauElement</code>s.
        */
        public static readonly ZTauElement[] Alpha1 =
        {
            null, new ZTauElement(BigInteger.One, BigInteger.Zero),
            null, new ZTauElement(MinusThree, BigInteger.One),
            null, new ZTauElement(MinusOne, BigInteger.One),
            null, new ZTauElement(BigInteger.One, BigInteger.One),
            null, new ZTauElement(MinusOne, MinusOne),
            null, new ZTauElement(BigInteger.One, MinusOne),
            null, new ZTauElement(BigInteger.Three, MinusOne),
            null, new ZTauElement(MinusOne, BigInteger.Zero),
        };

        /**
        * The <code>&#945;<sub>u</sub></code>'s for <code>a=1</code> as an array
        * of TNAFs.
        */
        public static readonly sbyte[][] Alpha1Tnaf =
        {
            null, new sbyte[]{1}, null, new sbyte[]{-1, 0, 1}, null, new sbyte[]{1, 0, 1}, null, new sbyte[]{-1, 0, 0, -1}
        };

        /**
        * Computes the norm of an element <code>&#955;</code> of
        * <code><b>Z</b>[&#964;]</code>.
        * @param mu The parameter <code>&#956;</code> of the elliptic curve.
        * @param lambda The element <code>&#955;</code> of
        * <code><b>Z</b>[&#964;]</code>.
        * @return The norm of <code>&#955;</code>.
        */
        public static BigInteger Norm(sbyte mu, ZTauElement lambda)
        {
            // s1 = u^2
            BigInteger s1 = lambda.u.Square();

            // s2 = u * v
            //BigInteger s2 = lambda.u.Multiply(lambda.v);

            // s3 = 2 * v^2
            //BigInteger s3 = lambda.v.Square().ShiftLeft(1);

            if (mu == 1)
            {
                //return s1.Add(s2).Add(s3);
                return lambda.v.ShiftLeft(1).Add(lambda.u).Multiply(lambda.v).Add(s1);
            }
            else if (mu == -1)
            {
                //return s1.Subtract(s2).Add(s3);
                return lambda.v.ShiftLeft(1).Subtract(lambda.u).Multiply(lambda.v).Add(s1);
            }
            else
            {
                throw new ArgumentException("mu must be 1 or -1");
            }
        }

        /**
        * Computes the norm of an element <code>&#955;</code> of
        * <code><b>R</b>[&#964;]</code>, where <code>&#955; = u + v&#964;</code>
        * and <code>u</code> and <code>u</code> are real numbers (elements of
        * <code><b>R</b></code>). 
        * @param mu The parameter <code>&#956;</code> of the elliptic curve.
        * @param u The real part of the element <code>&#955;</code> of
        * <code><b>R</b>[&#964;]</code>.
        * @param v The <code>&#964;</code>-adic part of the element
        * <code>&#955;</code> of <code><b>R</b>[&#964;]</code>.
        * @return The norm of <code>&#955;</code>.
        */
        public static SimpleBigDecimal Norm(sbyte mu, SimpleBigDecimal u, SimpleBigDecimal v)
        {
            SimpleBigDecimal norm;

            // s1 = u^2
            SimpleBigDecimal s1 = u.Multiply(u);

            // s2 = u * v
            SimpleBigDecimal s2 = u.Multiply(v);

            // s3 = 2 * v^2
            SimpleBigDecimal s3 = v.Multiply(v).ShiftLeft(1);

            if (mu == 1)
            {
                norm = s1.Add(s2).Add(s3);
            }
            else if (mu == -1)
            {
                norm = s1.Subtract(s2).Add(s3);
            }
            else
            {
                throw new ArgumentException("mu must be 1 or -1");
            }

            return norm;
        }

        /**
        * Rounds an element <code>&#955;</code> of <code><b>R</b>[&#964;]</code>
        * to an element of <code><b>Z</b>[&#964;]</code>, such that their difference
        * has minimal norm. <code>&#955;</code> is given as
        * <code>&#955; = &#955;<sub>0</sub> + &#955;<sub>1</sub>&#964;</code>.
        * @param lambda0 The component <code>&#955;<sub>0</sub></code>.
        * @param lambda1 The component <code>&#955;<sub>1</sub></code>.
        * @param mu The parameter <code>&#956;</code> of the elliptic curve. Must
        * equal 1 or -1.
        * @return The rounded element of <code><b>Z</b>[&#964;]</code>.
        * @throws ArgumentException if <code>lambda0</code> and
        * <code>lambda1</code> do not have same scale.
        */
        public static ZTauElement Round(SimpleBigDecimal lambda0,
            SimpleBigDecimal lambda1, sbyte mu)
        {
            int scale = lambda0.Scale;
            if (lambda1.Scale != scale)
                throw new ArgumentException("lambda0 and lambda1 do not have same scale");

            if (!((mu == 1) || (mu == -1)))
                throw new ArgumentException("mu must be 1 or -1");

            BigInteger f0 = lambda0.Round();
            BigInteger f1 = lambda1.Round();

            SimpleBigDecimal eta0 = lambda0.Subtract(f0);
            SimpleBigDecimal eta1 = lambda1.Subtract(f1);

            // eta = 2*eta0 + mu*eta1
            SimpleBigDecimal eta = eta0.Add(eta0);
            if (mu == 1)
            {
                eta = eta.Add(eta1);
            }
            else
            {
                // mu == -1
                eta = eta.Subtract(eta1);
            }

            // check1 = eta0 - 3*mu*eta1
            // check2 = eta0 + 4*mu*eta1
            SimpleBigDecimal threeEta1 = eta1.Add(eta1).Add(eta1);
            SimpleBigDecimal fourEta1 = threeEta1.Add(eta1);
            SimpleBigDecimal check1;
            SimpleBigDecimal check2;
            if (mu == 1)
            {
                check1 = eta0.Subtract(threeEta1);
                check2 = eta0.Add(fourEta1);
            }
            else
            {
                // mu == -1
                check1 = eta0.Add(threeEta1);
                check2 = eta0.Subtract(fourEta1);
            }

            sbyte h0 = 0;
            sbyte h1 = 0;

            // if eta >= 1
            if (eta.CompareTo(BigInteger.One) >= 0)
            {
                if (check1.CompareTo(MinusOne) < 0)
                {
                    h1 = mu;
                }
                else
                {
                    h0 = 1;
                }
            }
            else
            {
                // eta < 1
                if (check2.CompareTo(BigInteger.Two) >= 0)
                {
                    h1 = mu;
                }
            }

            // if eta < -1
            if (eta.CompareTo(MinusOne) < 0)
            {
                if (check1.CompareTo(BigInteger.One) >= 0)
                {
                    h1 = (sbyte)-mu;
                }
                else
                {
                    h0 = -1;
                }
            }
            else
            {
                // eta >= -1
                if (check2.CompareTo(MinusTwo) < 0)
                {
                    h1 = (sbyte)-mu;
                }
            }

            BigInteger q0 = f0.Add(BigInteger.ValueOf(h0));
            BigInteger q1 = f1.Add(BigInteger.ValueOf(h1));
            return new ZTauElement(q0, q1);
        }

        /**
        * Approximate division by <code>n</code>. For an integer
        * <code>k</code>, the value <code>&#955; = s k / n</code> is
        * computed to <code>c</code> bits of accuracy.
        * @param k The parameter <code>k</code>.
        * @param s The curve parameter <code>s<sub>0</sub></code> or
        * <code>s<sub>1</sub></code>.
        * @param vm The Lucas Sequence element <code>V<sub>m</sub></code>.
        * @param a The parameter <code>a</code> of the elliptic curve.
        * @param m The bit length of the finite field
        * <code><b>F</b><sub>m</sub></code>.
        * @param c The number of bits of accuracy, i.e. the scale of the returned
        * <code>SimpleBigDecimal</code>.
        * @return The value <code>&#955; = s k / n</code> computed to
        * <code>c</code> bits of accuracy.
        */
        public static SimpleBigDecimal ApproximateDivisionByN(BigInteger k,
            BigInteger s, BigInteger vm, sbyte a, int m, int c)
        {
            int _k = (m + 5)/2 + c;
            BigInteger ns = k.ShiftRight(m - _k - 2 + a);

            BigInteger gs = s.Multiply(ns);

            BigInteger hs = gs.ShiftRight(m);

            BigInteger js = vm.Multiply(hs);

            BigInteger gsPlusJs = gs.Add(js);
            BigInteger ls = gsPlusJs.ShiftRight(_k-c);
            if (gsPlusJs.TestBit(_k-c-1))
            {
                // round up
                ls = ls.Add(BigInteger.One);
            }

            return new SimpleBigDecimal(ls, c);
        }

        /**
        * Computes the <code>&#964;</code>-adic NAF (non-adjacent form) of an
        * element <code>&#955;</code> of <code><b>Z</b>[&#964;]</code>.
        * @param mu The parameter <code>&#956;</code> of the elliptic curve.
        * @param lambda The element <code>&#955;</code> of
        * <code><b>Z</b>[&#964;]</code>.
        * @return The <code>&#964;</code>-adic NAF of <code>&#955;</code>.
        */
        public static sbyte[] TauAdicNaf(sbyte mu, ZTauElement lambda)
        {
            if (!((mu == 1) || (mu == -1))) 
                throw new ArgumentException("mu must be 1 or -1");

            BigInteger norm = Norm(mu, lambda);

            // Ceiling of log2 of the norm 
            int log2Norm = norm.BitLength;

            // If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
            int maxLength = log2Norm > 30 ? log2Norm + 4 : 34;

            // The array holding the TNAF
            sbyte[] u = new sbyte[maxLength];
            int i = 0;

            // The actual length of the TNAF
            int length = 0;

            BigInteger r0 = lambda.u;
            BigInteger r1 = lambda.v;

            while(!((r0.Equals(BigInteger.Zero)) && (r1.Equals(BigInteger.Zero))))
            {
                // If r0 is odd
                if (r0.TestBit(0)) 
                {
                    u[i] = (sbyte) BigInteger.Two.Subtract((r0.Subtract(r1.ShiftLeft(1))).Mod(Four)).IntValue;

                    // r0 = r0 - u[i]
                    if (u[i] == 1)
                    {
                        r0 = r0.ClearBit(0);
                    }
                    else
                    {
                        // u[i] == -1
                        r0 = r0.Add(BigInteger.One);
                    }
                    length = i;
                }
                else
                {
                    u[i] = 0;
                }

                BigInteger t = r0;
                BigInteger s = r0.ShiftRight(1);
                if (mu == 1) 
                {
                    r0 = r1.Add(s);
                }
                else
                {
                    // mu == -1
                    r0 = r1.Subtract(s);
                }

                r1 = t.ShiftRight(1).Negate();
                i++;
            }

            length++;

            // Reduce the TNAF array to its actual length
            sbyte[] tnaf = new sbyte[length];
            Array.Copy(u, 0, tnaf, 0, length);
            return tnaf;
        }

        /**
        * Applies the operation <code>&#964;()</code> to an
        * <code>AbstractF2mPoint</code>. 
        * @param p The AbstractF2mPoint to which <code>&#964;()</code> is applied.
        * @return <code>&#964;(p)</code>
        */
        public static AbstractF2mPoint Tau(AbstractF2mPoint p)
        {
            return p.Tau();
        }

        /**
        * Returns the parameter <code>&#956;</code> of the elliptic curve.
        * @param curve The elliptic curve from which to obtain <code>&#956;</code>.
        * The curve must be a Koblitz curve, i.e. <code>a</code> Equals
        * <code>0</code> or <code>1</code> and <code>b</code> Equals
        * <code>1</code>. 
        * @return <code>&#956;</code> of the elliptic curve.
        * @throws ArgumentException if the given ECCurve is not a Koblitz
        * curve.
        */
        public static sbyte GetMu(AbstractF2mCurve curve)
        {
            BigInteger a = curve.A.ToBigInteger();

            sbyte mu;
            if (a.SignValue == 0)
            {
                mu = -1;
            }
            else if (a.Equals(BigInteger.One))
            {
                mu = 1;
            }
            else
            {
                throw new ArgumentException("No Koblitz curve (ABC), TNAF multiplication not possible");
            }
            return mu;
        }

        public static sbyte GetMu(ECFieldElement curveA)
        {
            return (sbyte)(curveA.IsZero ? -1 : 1);
        }

        public static sbyte GetMu(int curveA)
        {
            return (sbyte)(curveA == 0 ? -1 : 1);
        }

        /**
        * Calculates the Lucas Sequence elements <code>U<sub>k-1</sub></code> and
        * <code>U<sub>k</sub></code> or <code>V<sub>k-1</sub></code> and
        * <code>V<sub>k</sub></code>.
        * @param mu The parameter <code>&#956;</code> of the elliptic curve.
        * @param k The index of the second element of the Lucas Sequence to be
        * returned.
        * @param doV If set to true, computes <code>V<sub>k-1</sub></code> and
        * <code>V<sub>k</sub></code>, otherwise <code>U<sub>k-1</sub></code> and
        * <code>U<sub>k</sub></code>.
        * @return An array with 2 elements, containing <code>U<sub>k-1</sub></code>
        * and <code>U<sub>k</sub></code> or <code>V<sub>k-1</sub></code>
        * and <code>V<sub>k</sub></code>.
        */
        public static BigInteger[] GetLucas(sbyte mu, int k, bool doV)
        {
            if (!(mu == 1 || mu == -1))
                throw new ArgumentException("mu must be 1 or -1");

            BigInteger u0, u1, u2;
            if (doV)
            {
                u0 = BigInteger.Two;
                u1 = BigInteger.ValueOf(mu);
            }
            else
            {
                u0 = BigInteger.Zero;
                u1 = BigInteger.One;
            }

            for (int i = 1; i < k; i++)
            {
                // u2 = mu*u1 - 2*u0;
                BigInteger s = u1;
                if (mu < 0)
                {
                    s = s.Negate();
                }

                u2 = s.Subtract(u0.ShiftLeft(1));
                u0 = u1;
                u1 = u2;
            }

            return new BigInteger[]{ u0, u1 };
        }

        /**
        * Computes the auxiliary value <code>t<sub>w</sub></code>. If the width is
        * 4, then for <code>mu = 1</code>, <code>t<sub>w</sub> = 6</code> and for
        * <code>mu = -1</code>, <code>t<sub>w</sub> = 10</code> 
        * @param mu The parameter <code>&#956;</code> of the elliptic curve.
        * @param w The window width of the WTNAF.
        * @return the auxiliary value <code>t<sub>w</sub></code>
        */
        public static BigInteger GetTw(sbyte mu, int w) 
        {
            if (w == 4)
            {
                if (mu == 1)
                {
                    return BigInteger.Six;
                }
                else
                {
                    // mu == -1
                    return BigInteger.Ten;
                }
            }
            else
            {
                // For w <> 4, the values must be computed
                BigInteger[] us = GetLucas(mu, w, false);
                return us[0].ShiftLeft(1).ModDivide(us[1], BigInteger.One.ShiftLeft(w));
            }
        }

        /**
        * Computes the auxiliary values <code>s<sub>0</sub></code> and
        * <code>s<sub>1</sub></code> used for partial modular reduction. 
        * @param curve The elliptic curve for which to compute
        * <code>s<sub>0</sub></code> and <code>s<sub>1</sub></code>.
        * @throws ArgumentException if <code>curve</code> is not a
        * Koblitz curve (Anomalous Binary Curve, ABC).
        */
        public static BigInteger[] GetSi(AbstractF2mCurve curve)
        {
            if (!curve.IsKoblitz)
                throw new ArgumentException("si is defined for Koblitz curves only");

            return GetSi(curve.FieldSize, curve.A.ToBigInteger().IntValue, curve.Cofactor);
        }

        public static BigInteger[] GetSi(int fieldSize, int curveA, BigInteger cofactor)
        {
            sbyte mu = GetMu(curveA);
            int shifts = GetShiftsForCofactor(cofactor);
            int index = fieldSize + 3 - curveA;
            BigInteger[] ui = GetLucas(mu, index, false);
            if (mu == 1)
            {
                ui[0] = ui[0].Negate();
                ui[1] = ui[1].Negate();
            }

            BigInteger dividend0 = BigInteger.One.Add(ui[1]).ShiftRight(shifts);
            BigInteger dividend1 = BigInteger.One.Add(ui[0]).ShiftRight(shifts).Negate();

            return new BigInteger[] { dividend0, dividend1 };
        }

        private static int GetShiftsForCofactor(BigInteger h)
        {
            if (h != null && h.BitLength < 4)
            {
                int hi = h.IntValue;
                if (hi == 2)
                    return 1;
                if (hi == 4)
                    return 2;
            }

            throw new ArgumentException("h (Cofactor) must be 2 or 4");
        }

        /**
        * Partial modular reduction modulo
        * <code>(&#964;<sup>m</sup> - 1)/(&#964; - 1)</code>.
        * @param k The integer to be reduced.
        * @param m The bitlength of the underlying finite field.
        * @param a The parameter <code>a</code> of the elliptic curve.
        * @param s The auxiliary values <code>s<sub>0</sub></code> and
        * <code>s<sub>1</sub></code>.
        * @param mu The parameter &#956; of the elliptic curve.
        * @param c The precision (number of bits of accuracy) of the partial
        * modular reduction.
        * @return <code>&#961; := k partmod (&#964;<sup>m</sup> - 1)/(&#964; - 1)</code>
        */
        public static ZTauElement PartModReduction(AbstractF2mCurve curve, BigInteger k, sbyte a, sbyte mu, sbyte c)
        {
            PartModPreCompCallback callback = new PartModPreCompCallback(curve, mu, true);
            PartModPreCompInfo preCompInfo = (PartModPreCompInfo)curve.Precompute(PRECOMP_NAME, callback);

            BigInteger vm = preCompInfo.Lucas;
            BigInteger s0 = preCompInfo.S0;
            BigInteger s1 = preCompInfo.S1;

            // d0 = s[0] + mu*s[1]; mu is either 1 or -1
            BigInteger d0;
            if (mu == 1)
            {
                d0 = s0.Add(s1);
            }
            else
            {
                d0 = s0.Subtract(s1);
            }

            int m = curve.FieldSize;
            SimpleBigDecimal lambda0 = ApproximateDivisionByN(k, s0, vm, a, m, c);
            SimpleBigDecimal lambda1 = ApproximateDivisionByN(k, s1, vm, a, m, c);

            ZTauElement q = Round(lambda0, lambda1, mu);

            // r0 = n - d0*q0 - 2*s1*q1
            BigInteger r0 = k.Subtract(d0.Multiply(q.u)).Subtract(
                s1.Multiply(q.v).ShiftLeft(1));

            // r1 = s1*q0 - s0*q1
            BigInteger r1 = s1.Multiply(q.u).Subtract(s0.Multiply(q.v));

            return new ZTauElement(r0, r1);
        }

        /**
        * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
        * by a <code>BigInteger</code> using the reduced <code>&#964;</code>-adic
        * NAF (RTNAF) method.
        * @param p The AbstractF2mPoint to Multiply.
        * @param k The <code>BigInteger</code> by which to Multiply <code>p</code>.
        * @return <code>k * p</code>
        */
        public static AbstractF2mPoint MultiplyRTnaf(AbstractF2mPoint p, BigInteger k)
        {
            AbstractF2mCurve curve = (AbstractF2mCurve)p.Curve;
            int a = curve.A.ToBigInteger().IntValue;
            sbyte mu = GetMu(a);

            ZTauElement rho = PartModReduction(curve, k, (sbyte)a, mu, (sbyte)10);

            return MultiplyTnaf(p, rho);
        }

        /**
        * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
        * by an element <code>&#955;</code> of <code><b>Z</b>[&#964;]</code>
        * using the <code>&#964;</code>-adic NAF (TNAF) method.
        * @param p The AbstractF2mPoint to Multiply.
        * @param lambda The element <code>&#955;</code> of
        * <code><b>Z</b>[&#964;]</code>.
        * @return <code>&#955; * p</code>
        */
        public static AbstractF2mPoint MultiplyTnaf(AbstractF2mPoint p, ZTauElement lambda)
        {
            AbstractF2mCurve curve = (AbstractF2mCurve)p.Curve;
            AbstractF2mPoint pNeg = (AbstractF2mPoint)p.Negate();
            sbyte mu = GetMu(curve.A);
            sbyte[] u = TauAdicNaf(mu, lambda);

            return MultiplyFromTnaf(p, pNeg, u);
        }

        /**
        * Multiplies a {@link org.bouncycastle.math.ec.AbstractF2mPoint AbstractF2mPoint}
        * by an element <code>&#955;</code> of <code><b>Z</b>[&#964;]</code>
        * using the <code>&#964;</code>-adic NAF (TNAF) method, given the TNAF
        * of <code>&#955;</code>.
        * @param p The AbstractF2mPoint to Multiply.
        * @param u The the TNAF of <code>&#955;</code>..
        * @return <code>&#955; * p</code>
        */
        public static AbstractF2mPoint MultiplyFromTnaf(AbstractF2mPoint p, AbstractF2mPoint pNeg, sbyte[] u)
        {
            ECCurve curve = p.Curve;
            AbstractF2mPoint q = (AbstractF2mPoint)curve.Infinity;
            int tauCount = 0;
            for (int i = u.Length - 1; i >= 0; i--)
            {
                ++tauCount;
                sbyte ui = u[i];
                if (ui != 0)
                {
                    q = q.TauPow(tauCount);
                    tauCount = 0;

                    ECPoint x = ui > 0 ? p : pNeg;
                    q = (AbstractF2mPoint)q.Add(x);
                }
            }
            if (tauCount > 0)
            {
                q = q.TauPow(tauCount);
            }
            return q;
        }

        /**
        * Computes the <code>[&#964;]</code>-adic window NAF of an element
        * <code>&#955;</code> of <code><b>Z</b>[&#964;]</code>.
        * @param mu The parameter &#956; of the elliptic curve.
        * @param lambda The element <code>&#955;</code> of
        * <code><b>Z</b>[&#964;]</code> of which to compute the
        * <code>[&#964;]</code>-adic NAF.
        * @param width The window width of the resulting WNAF.
        * @param pow2w 2<sup>width</sup>.
        * @param tw The auxiliary value <code>t<sub>w</sub></code>.
        * @param alpha The <code>&#945;<sub>u</sub></code>'s for the window width.
        * @return The <code>[&#964;]</code>-adic window NAF of
        * <code>&#955;</code>.
        */
        public static sbyte[] TauAdicWNaf(sbyte mu, ZTauElement lambda, int width, int tw, ZTauElement[] alpha)
        {
            if (!(mu == 1 || mu == -1))
                throw new ArgumentException("mu must be 1 or -1");

            BigInteger norm = Norm(mu, lambda);

            // Ceiling of log2 of the norm 
            int log2Norm = norm.BitLength;

            // If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
            int maxLength = log2Norm > 30 ? log2Norm + 4 + width : 34 + width;

            // The array holding the TNAF
            sbyte[] u = new sbyte[maxLength];

            int pow2Width = 1 << width;
            int pow2Mask = pow2Width - 1;
            int s = 32 - width;

            // Split lambda into two BigIntegers to simplify calculations
            BigInteger R0 = lambda.u;
            BigInteger R1 = lambda.v;
            int uPos = 0;

            long r0_64, r1_64;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<int> alphaUs = stackalloc int[alpha.Length];
            Span<int> alphaVs = stackalloc int[alpha.Length];
#else
            int[] alphaUs = new int[alpha.Length];
            int[] alphaVs = new int[alpha.Length];
#endif
            for (int i = 1; i < alpha.Length; i += 2)
            {
                alphaUs[i] = alpha[i].u.IntValueExact;
                alphaVs[i] = alpha[i].v.IntValueExact;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            int len = (System.Math.Max(R0.BitLength, R1.BitLength) + 33) >> 5;
            if (len <= 2)
            {
                r0_64 = R0.LongValueExact;
                r1_64 = R1.LongValueExact;
            }
            else
            {
                Span<uint> r0 = len <= 32 ? stackalloc uint[len] : new uint[len];
                Span<uint> r1 = len <= 32 ? stackalloc uint[len] : new uint[len];
                Span<uint> rt = len <= 32 ? stackalloc uint[len] : new uint[len];

                BigIntegers.AsUint32ArrayLittleEndian(R0, r0);
                BigIntegers.AsUint32ArrayLittleEndian(R1, r1);

                long muMask = mu < 0 ? -1L : 0L;

                while (len > 2)
                {
                    if ((r0[0] & 1U) != 0U)
                    {
                        int uVal = (int)r0[0] + ((int)r1[0] * tw);
                        int alphaPos = uVal & pow2Mask;

                        u[uPos] = (sbyte)((uVal << s) >> s);
                        Nat.SubInt32From(len, alphaUs[alphaPos], r0);
                        Nat.SubInt32From(len, alphaVs[alphaPos], r1);
                    }

                    ++uPos;

                    Nat.ShiftDownBit(len, r0, r0[len - 1] >> 31, rt);
                    if (mu == 1)
                    {
                        Nat.Add(len, r1, rt, r0);
                    }
                    else // mu == -1
                    {
                        Nat.Sub(len, r1, rt, r0);
                    }
                    Nat.Negate(len, rt, r1);

                    int r0Sign = (int)r0[len - 1] >> 31;
                    int r1Sign = (int)r1[len - 1] >> 31;

                    int check = ((int)r0[len - 1] ^ r0Sign)
                              | (((int)r0[len - 2] >> 30) ^ r0Sign)
                              | ((int)r1[len - 1] ^ r1Sign)
                              | (((int)r1[len - 2] >> 30) ^ r1Sign);

                    len -= Convert.ToInt32(check == 0);
                }

                r0_64 = (long)r0[1] << 32 | r0[0];
                r1_64 = (long)r1[1] << 32 | r1[0];
            }
#else
            // while lambda <> (0, 0)
            while (R0.BitLength > 62 || R1.BitLength > 62)
            {
                if (R0.TestBit(0)) 
                {
                    int uVal = R0.IntValue + (R1.IntValue * tw);
                    int alphaPos = uVal & pow2Mask;

                    u[uPos] = (sbyte)((uVal << s) >> s);
                    R0 = R0.Subtract(alpha[alphaPos].u);
                    R1 = R1.Subtract(alpha[alphaPos].v);
                }

                ++uPos;

                BigInteger t = R0.ShiftRight(1);
                if (mu == 1)
                {
                    R0 = R1.Add(t);
                }
                else // mu == -1
                {
                    R0 = R1.Subtract(t);
                }
                R1 = t.Negate();
            }

            r0_64 = R0.LongValueExact;
            r1_64 = R1.LongValueExact;
#endif

            // while lambda <> (0, 0)
            while ((r0_64 | r1_64) != 0L)
            {
                if ((r0_64 & 1L) != 0L)
                {
                    int uVal = (int)r0_64 + ((int)r1_64 * tw);
                    int alphaPos = uVal & pow2Mask;

                    u[uPos] = (sbyte)((uVal << s) >> s);
                    r0_64 -= alphaUs[alphaPos];
                    r1_64 -= alphaVs[alphaPos];
                }

                ++uPos;

                long t_64 = r0_64 >> 1;
                if (mu == 1)
                {
                    r0_64 = r1_64 + t_64;
                }
                else // mu == -1
                {
                    r0_64 = r1_64 - t_64;
                }
                r1_64 = -t_64;
            }

            return u;
        }

        /**
        * Does the precomputation for WTNAF multiplication.
        * @param p The <code>ECPoint</code> for which to do the precomputation.
        * @param a The parameter <code>a</code> of the elliptic curve.
        * @return The precomputation array for <code>p</code>. 
        */
        public static AbstractF2mPoint[] GetPreComp(AbstractF2mPoint p, sbyte a)
        {
            AbstractF2mPoint pNeg = (AbstractF2mPoint)p.Negate();
            sbyte[][] alphaTnaf = (a == 0) ? Tnaf.Alpha0Tnaf : Tnaf.Alpha1Tnaf;

            AbstractF2mPoint[] pu = new AbstractF2mPoint[(uint)(alphaTnaf.Length + 1) >> 1];
            pu[0] = p;

            int precompLen = alphaTnaf.Length;
            for (uint i = 3; i < precompLen; i += 2)
            {
                pu[i >> 1] = Tnaf.MultiplyFromTnaf(p, pNeg, alphaTnaf[i]);
            }

            p.Curve.NormalizeAll(pu);

            return pu;
        }

        private sealed class PartModPreCompCallback
            : IPreCompCallback
        {
            private readonly AbstractF2mCurve m_curve;
            private readonly sbyte m_mu;
            private readonly bool m_doV;

            internal PartModPreCompCallback(AbstractF2mCurve curve, sbyte mu, bool doV)
            {
                m_curve = curve;
                m_mu = mu;
                m_doV = doV;
            }

            public PreCompInfo Precompute(PreCompInfo existing)
            {
                if (existing is PartModPreCompInfo)
                    return existing;

                BigInteger lucas;
                if (m_curve.IsKoblitz)
                {
                    /*
                     * Jerome A. Solinas, "Improved Algorithms for Arithmetic on Anomalous Binary Curves", (21).
                     */
                    lucas = BigInteger.One.ShiftLeft(m_curve.FieldSize).Add(BigInteger.One).Subtract(
                        m_curve.Order.Multiply(m_curve.Cofactor));
                }
                else
                {
                    lucas = GetLucas(m_mu, m_curve.FieldSize, m_doV)[1];
                }

                var si = GetSi(m_curve);

                return new PartModPreCompInfo(lucas, si[0], si[1]);
            }
        }

        private sealed class PartModPreCompInfo
            : PreCompInfo
        {
            private readonly BigInteger m_lucas;
            private readonly BigInteger m_s0;
            private readonly BigInteger m_s1;

            internal PartModPreCompInfo(BigInteger lucas, BigInteger s0, BigInteger s1)
            {
                m_lucas = lucas;
                m_s0 = s0;
                m_s1 = s1;
            }

            internal BigInteger Lucas => m_lucas;
            internal BigInteger S0 => m_s0;
            internal BigInteger S1 => m_s1;
        }
    }
}
