using System;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecT163K1Point
        : AbstractF2mPoint
    {
        internal SecT163K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
        }

        internal SecT163K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        protected override ECPoint Detach()
        {
            return new SecT163K1Point(null, this.AffineXCoord, this.AffineYCoord);
        }

        public override ECFieldElement YCoord
        {
            get
            {
                ECFieldElement X = RawXCoord, L = RawYCoord;

                if (this.IsInfinity || X.IsZero)
                    return L;

                // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
                ECFieldElement Y = L.Add(X).Multiply(X);

                ECFieldElement Z = RawZCoords[0];
                if (!Z.IsOne)
                {
                    Y = Y.Divide(Z);
                }

                return Y;
            }
        }

        protected internal override bool CompressionYTilde
        {
            get
            {
                ECFieldElement X = this.RawXCoord;
                if (X.IsZero)
                    return false;

                ECFieldElement Y = this.RawYCoord;

                // Y is actually Lambda (X + Y/X) here
                return Y.TestBitZero() != X.TestBitZero();
            }
        }

        public override ECPoint Add(ECPoint b)
        {
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return this;

            ECCurve curve = this.Curve;

            SecT163FieldElement X1 = (SecT163FieldElement)this.RawXCoord;
            SecT163FieldElement X2 = (SecT163FieldElement)b.RawXCoord;

            if (X1.IsZero)
            {
                if (X2.IsZero)
                    return curve.Infinity;

                return b.Add(this);
            }

            SecT163FieldElement L1 = (SecT163FieldElement)this.RawYCoord, Z1 = (SecT163FieldElement)this.RawZCoords[0];
            SecT163FieldElement L2 = (SecT163FieldElement)b.RawYCoord, Z2 = (SecT163FieldElement)b.RawZCoords[0];

            ulong[] tt0 = Nat192.CreateExt64();
            ulong[] t1 = Nat192.Create64();
            ulong[] t2 = Nat192.Create64();
            ulong[] t3 = Nat192.Create64();

            bool Z1IsOne = Z1.IsOne;
            if (Z1IsOne)
            {
                Nat192.Copy64(X2.x, t1);                    // U2
                Nat192.Copy64(L2.x, t2);                    // S2
            }
            else
            {
                SecT163Field.Multiply(X2.x, Z1.x, t1);      // U2
                SecT163Field.Multiply(L2.x, Z1.x, t2);      // S2
            }

            bool Z2IsOne = Z2.IsOne;
            if (Z2IsOne)
            {
                Nat192.Copy64(X1.x, t3);                    // U1
                Nat192.Copy64(L1.x, tt0);                   // S1
            }
            else
            {
                SecT163Field.Multiply(X1.x, Z2.x, t3);      // U1
                SecT163Field.Multiply(L1.x, Z2.x, tt0);     // S1
            }

            SecT163Field.AddTo(tt0, t2);                    // A
            SecT163Field.Add(t3, t1, tt0);                  // B

            if (Nat192.IsZero64(tt0))
            {
                if (Nat192.IsZero64(t2))
                    return Twice();

                return curve.Infinity;
            }

            if (X2.IsZero)
            {
                // TODO This can probably be optimized quite a bit
                ECPoint p = this.Normalize();
                X1 = (SecT163FieldElement)p.XCoord;
                ECFieldElement Y1 = p.YCoord;

                ECFieldElement Y2 = L2;
                ECFieldElement L = Y1.Add(Y2).Divide(X1);

                ECFieldElement X3 = L.Square().Add(L).Add(X1);
                if (X3.IsZero)
                    return new SecT163K1Point(curve, X3, curve.B);

                ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
                ECFieldElement L3 = Y3.Divide(X3).Add(X3);
                ECFieldElement Z3 = curve.FromBigInteger(BigInteger.One);

                return new SecT163K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }

            SecT163Field.Square(tt0, tt0);

            SecT163Field.Multiply(t3, t2, t3);      // AU1
            SecT163Field.Multiply(t1, t2, t1);      // AU2

            ulong[] _X3 = t3;
            SecT163Field.Multiply(_X3, t1, _X3);
            if (Nat192.IsZero64(_X3))
                return new SecT163K1Point(curve, new SecT163FieldElement(_X3), curve.B);

            ulong[] _Z3 = t2;
            SecT163Field.Multiply(_Z3, tt0, _Z3);   // ABZ2
            if (!Z2IsOne)
            {
                SecT163Field.Multiply(_Z3, Z2.x, _Z3);
            }

            ulong[] _L3 = t1;
            SecT163Field.AddTo(tt0, _L3);
            SecT163Field.SquareExt(_L3, tt0);
            SecT163Field.Add(L1.x, Z1.x, _L3);
            SecT163Field.MultiplyAddToExt(_Z3, _L3, tt0);
            SecT163Field.Reduce(tt0, _L3);

            if (!Z1IsOne)
            {
                SecT163Field.Multiply(_Z3, Z1.x, _Z3);
            }

            return new SecT163K1Point(curve, new SecT163FieldElement(_X3), new SecT163FieldElement(_L3),
                new ECFieldElement[]{ new SecT163FieldElement(_Z3) });
        }

        public override ECPoint Twice()
        {
            if (this.IsInfinity)
            {
                return this;
            }

            ECCurve curve = this.Curve;

            ECFieldElement X1 = this.RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is its own additive inverse
                return curve.Infinity;
            }

            ECFieldElement L1 = this.RawYCoord, Z1 = this.RawZCoords[0];

            bool Z1IsOne = Z1.IsOne;
            ECFieldElement L1Z1 = Z1IsOne ? L1 : L1.Multiply(Z1);
            ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.Square();
            ECFieldElement T = L1.Square().Add(L1Z1).Add(Z1Sq);
            if (T.IsZero)
            {
                return new SecT163K1Point(curve, T, curve.B);
            }

            ECFieldElement X3 = T.Square();
            ECFieldElement Z3 = Z1IsOne ? T : T.Multiply(Z1Sq);

            ECFieldElement t1 = L1.Add(X1).Square();
            ECFieldElement L3 = t1.Add(T).Add(Z1Sq).Multiply(t1).Add(X3);

            return new SecT163K1Point(curve, X3, L3, new ECFieldElement[] { Z3 });
        }

        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECCurve curve = this.Curve;

            ECFieldElement X1 = this.RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is its own additive inverse
                return b;
            }

            // NOTE: TwicePlus() only optimized for lambda-affine argument
            ECFieldElement X2 = b.RawXCoord, Z2 = b.RawZCoords[0];
            if (X2.IsZero || !Z2.IsOne)
            {
                return Twice().Add(b);
            }

            ECFieldElement L1 = this.RawYCoord, Z1 = this.RawZCoords[0];
            ECFieldElement L2 = b.RawYCoord;

            ECFieldElement X1Sq = X1.Square();
            ECFieldElement L1Sq = L1.Square();
            ECFieldElement Z1Sq = Z1.Square();
            ECFieldElement L1Z1 = L1.Multiply(Z1);

            ECFieldElement T = Z1Sq.Add(L1Sq).Add(L1Z1);
            ECFieldElement A = L2.Multiply(Z1Sq).Add(L1Sq).MultiplyPlusProduct(T, X1Sq, Z1Sq);
            ECFieldElement X2Z1Sq = X2.Multiply(Z1Sq);
            ECFieldElement B = X2Z1Sq.Add(T).Square();

            if (B.IsZero)
            {
                if (A.IsZero)
                    return b.Twice();

                return curve.Infinity;
            }

            if (A.IsZero)
            {
                return new SecT163K1Point(curve, A, curve.B);
            }

            ECFieldElement X3 = A.Square().Multiply(X2Z1Sq);
            ECFieldElement Z3 = A.Multiply(B).Multiply(Z1Sq);
            ECFieldElement L3 = A.Add(B).Square().MultiplyPlusProduct(T, L2.AddOne(), Z3);

            return new SecT163K1Point(curve, X3, L3, new ECFieldElement[] { Z3 });
        }

        public override ECPoint Negate()
        {
            if (this.IsInfinity)
                return this;

            ECFieldElement X = this.RawXCoord;
            if (X.IsZero)
                return this;

            // L is actually Lambda (X + Y/X) here
            ECFieldElement L = this.RawYCoord, Z = this.RawZCoords[0];
            return new SecT163K1Point(Curve, X, L.Add(Z), new ECFieldElement[] { Z });
        }
    }
}
