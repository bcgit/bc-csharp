using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Asn1.UA
{
    /**
     * DSTU4145 encodes points somewhat differently than X9.62
     * It compresses the point to the size of the field element
     */
    public static class Dstu4145PointEncoder
    {
        private static ECFieldElement Trace(ECFieldElement fe)
        {
            ECFieldElement t = fe;
            for (int i = 1; i < fe.FieldSize; ++i)
            {
                t = t.Square().Add(fe);
            }
            return t;
        }

        /**
         * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
         * D.1.6) The other solution is <code>z + 1</code>.
         *
         * @param beta The value to solve the quadratic equation for.
         * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
         *         <code>null</code> if no solution exists.
         */
        private static ECFieldElement SolveQuadraticEquation(ECCurve curve, ECFieldElement beta)
        {
            if (beta.IsZero)
                return beta;

            ECFieldElement zeroElement = curve.FromBigInteger(BigInteger.Zero);

            ECFieldElement z;
            ECFieldElement gamma;

            Random rand = new Random();
            int m = beta.FieldSize;
            do
            {
                ECFieldElement t = curve.FromBigInteger(new BigInteger(m, rand));
                z = zeroElement;
                ECFieldElement w = beta;
                for (int i = 1; i < m ; i++)
                {
                    ECFieldElement w2 = w.Square();
                    z = z.Square().Add(w2.Multiply(t));
                    w = w2.Add(beta);
                }

                if (!w.IsZero)
                    return null;

                gamma = z.Square().Add(z);
            }
            while (gamma.IsZero);

            return z;
        }

        public static byte[] EncodePoint(ECPoint q)
        {
            q = q.Normalize();

            ECFieldElement x = q.AffineXCoord;

            byte[] bytes = x.GetEncoded();

            if (!x.IsZero)
            {
                ECFieldElement z = q.AffineYCoord.Divide(x);
                if (Trace(z).IsOne)
                {
                    bytes[bytes.Length - 1] |= 0x01;
                }
                else
                {
                    bytes[bytes.Length - 1] &= 0xFE;
                }
            }

            return bytes;
        }

        public static ECPoint DecodePoint(ECCurve curve, byte[] bytes)
        {
            ECFieldElement k = curve.FromBigInteger(BigInteger.ValueOf(bytes[bytes.Length - 1] & 0x1));

            ECFieldElement xp = curve.FromBigInteger(new BigInteger(1, bytes));
            if (!Trace(xp).Equals(curve.A))
            {
                xp = xp.AddOne();
            }

            ECFieldElement yp = null;
            if (xp.IsZero)
            {
                yp = curve.B.Sqrt();
            }
            else
            {
                ECFieldElement beta = xp.Square().Invert().Multiply(curve.B).Add(curve.A).Add(xp);
                ECFieldElement z = SolveQuadraticEquation(curve, beta);
                if (z != null)
                {
                    if (!Trace(z).Equals(k))
                    {
                        z = z.AddOne();
                    }
                    yp = xp.Multiply(z);
                }
            }

            if (yp == null)
                throw new ArgumentException("Invalid point compression");

            return curve.ValidatePoint(xp.ToBigInteger(), yp.ToBigInteger());
        }
    }
}
