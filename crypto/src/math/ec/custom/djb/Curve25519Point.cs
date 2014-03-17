using System;

using Org.BouncyCastle.Math.EC.Custom.Sec;

namespace Org.BouncyCastle.Math.EC.Custom.Djb
{
    internal class Curve25519Point
        :   ECPointBase
    {
        /**
         * Create a point which encodes with point compression.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * 
         * @deprecated Use ECCurve.createPoint to construct points
         */
        public Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
            :   this(curve, x, y, false)
        {
        }

        /**
         * Create a point that encodes with or without point compresion.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * @param withCompression if true encode with point compression
         * 
         * @deprecated per-point compression property will be removed, refer {@link #getEncoded(bool)}
         */
        public Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, bool withCompression)
            :   base(curve, x, y, withCompression)
        {
            if ((x == null) != (y == null))
                throw new ArgumentException("Exactly one of the field elements is null");
        }

        internal Curve25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
            : base(curve, x, y, zs, withCompression)
        {
        }

        protected override ECPoint Detach()
        {
            return new Curve25519Point(null, AffineXCoord, AffineYCoord);
        }

        protected internal override bool CompressionYTilde
        {
            get { return this.AffineYCoord.TestBitZero(); }
        }

        public override ECFieldElement GetZCoord(int index)
        {
            if (index == 1)
            {
                return GetJacobianModifiedW();
            }

            return base.GetZCoord(index);
        }

        public override ECPoint Add(ECPoint b)
        {
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return this;
            if (this == b)
                return Twice();

            ECCurve curve = this.Curve;

            ECFieldElement X1 = this.RawXCoord, Y1 = this.RawYCoord;
            ECFieldElement X2 = b.RawXCoord, Y2 = b.RawYCoord;

            ECFieldElement Z1 = this.RawZCoords[0];
            ECFieldElement Z2 = b.RawZCoords[0];

            bool Z1IsOne = Z1.IsOne;

            ECFieldElement Z1Squared, U2, S2;
            if (Z1IsOne)
            {
                Z1Squared = Z1; U2 = X2; S2 = Y2;
            }
            else
            {
                Z1Squared = Z1.Square();
                U2 = Z1Squared.Multiply(X2);
                ECFieldElement Z1Cubed = Z1Squared.Multiply(Z1);
                S2 = Z1Cubed.Multiply(Y2);
            }

            bool Z2IsOne = Z2.IsOne;
            ECFieldElement Z2Squared, U1, S1;
            if (Z2IsOne)
            {
                Z2Squared = Z2; U1 = X1; S1 = Y1;
            }
            else
            {
                Z2Squared = Z2.Square();
                U1 = Z2Squared.Multiply(X1); 
                ECFieldElement Z2Cubed = Z2Squared.Multiply(Z2);
                S1 = Z2Cubed.Multiply(Y1);
            }

            ECFieldElement H = U1.Subtract(U2);
            ECFieldElement R = S1.Subtract(S2);

            // Check if b == this or b == -this
            if (H.IsZero)
            {
                if (R.IsZero)
                {
                    // this == b, i.e. this must be doubled
                    return this.Twice();
                }

                // this == -b, i.e. the result is the point at infinity
                return curve.Infinity;
            }

            ECFieldElement HSquared = H.Square();
            ECFieldElement G = HSquared.Multiply(H);
            ECFieldElement V = HSquared.Multiply(U1);

            ECFieldElement X3 = R.Square().Add(G).Subtract(Two(V));
            ECFieldElement Y3 = V.Subtract(X3).MultiplyMinusProduct(R, G, S1);

            ECFieldElement Z3 = H;
            if (!Z1IsOne)
            {
                Z3 = Z3.Multiply(Z1);
            }
            if (!Z2IsOne)
            {
                Z3 = Z3.Multiply(Z2);
            }

            ECFieldElement Z3Squared = (Z3 == H) ? HSquared : null;

            // TODO If the result will only be used in a subsequent addition, we don't need W3
            ECFieldElement W3 = CalculateJacobianModifiedW(Z3, Z3Squared);

            ECFieldElement[] zs = new ECFieldElement[]{ Z3, W3 };

            return new Curve25519Point(curve, X3, Y3, zs, IsCompressed);
        }

        public override ECPoint Twice()
        {
            if (this.IsInfinity)
                return this;

            ECCurve curve = this.Curve;

            ECFieldElement Y1 = this.RawYCoord;
            if (Y1.IsZero) 
                return curve.Infinity;

            return TwiceJacobianModified(true);
        }

        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this == b)
                return ThreeTimes();
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECFieldElement Y1 = this.RawYCoord;
            if (Y1.IsZero) 
                return b;

            return TwiceJacobianModified(false).Add(b);
        }

        public override ECPoint ThreeTimes()
        {
            if (this.IsInfinity || this.RawYCoord.IsZero)
                return this;

            return TwiceJacobianModified(false).Add(this);
        }

        protected virtual ECFieldElement Two(ECFieldElement x)
        {
            return x.Add(x);
        }

        protected virtual ECFieldElement Three(ECFieldElement x)
        {
            return Two(x).Add(x);
        }

        public override ECPoint Subtract(ECPoint b)
        {
            if (b.IsInfinity)
                return this;

            return Add(b.Negate());
        }

        public override ECPoint Negate()
        {
            if (IsInfinity)
                return this;

            return new Curve25519Point(Curve, RawXCoord, RawYCoord.Negate(), RawZCoords, IsCompressed);
        }

        protected virtual ECFieldElement CalculateJacobianModifiedW(ECFieldElement Z, ECFieldElement ZSquared)
        {
            ECFieldElement a4 = this.Curve.A;
            if (Z.IsOne)
                return a4;

            if (ZSquared == null)
            {
                ZSquared = Z.Square();
            }

            return ZSquared.Square().Multiply(a4);
        }

        protected virtual ECFieldElement GetJacobianModifiedW()
        {
            ECFieldElement[] ZZ = this.RawZCoords;
            ECFieldElement W = ZZ[1];
            if (W == null)
            {
                // NOTE: Rarely, TwicePlus will result in the need for a lazy W1 calculation here
                ZZ[1] = W = CalculateJacobianModifiedW(ZZ[0], null);
            }
            return W;
        }

        protected virtual Curve25519Point TwiceJacobianModified(bool calculateW)
        {
            ECFieldElement X1 = this.RawXCoord, Y1 = this.RawYCoord, Z1 = this.RawZCoords[0], W1 = GetJacobianModifiedW();

            ECFieldElement X1Squared = X1.Square();
            ECFieldElement M = Three(X1Squared).Add(W1);
            ECFieldElement _2Y1 = Two(Y1);
            ECFieldElement _2Y1Squared = _2Y1.Multiply(Y1);
            ECFieldElement S = Two(X1.Multiply(_2Y1Squared));
            ECFieldElement X3 = M.Square().Subtract(Two(S));
            ECFieldElement _4T = _2Y1Squared.Square();
            ECFieldElement _8T = Two(_4T);
            ECFieldElement Y3 = M.Multiply(S.Subtract(X3)).Subtract(_8T);
            ECFieldElement W3 = calculateW ? Two(_8T.Multiply(W1)) : null;
            ECFieldElement Z3 = Z1.IsOne ? _2Y1 : _2Y1.Multiply(Z1);

            return new Curve25519Point(this.Curve, X3, Y3, new ECFieldElement[] { Z3, W3 }, IsCompressed);
        }
    }
}
