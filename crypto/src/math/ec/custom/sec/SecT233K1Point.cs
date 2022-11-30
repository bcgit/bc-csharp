using System;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecT233K1Point
        : AbstractF2mPoint
    {
        internal SecT233K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
        }

        internal SecT233K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        protected override ECPoint Detach()
        {
            return new SecT233K1Point(null, this.AffineXCoord, this.AffineYCoord);
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

            SecT233FieldElement X1 = (SecT233FieldElement)this.RawXCoord;
            SecT233FieldElement X2 = (SecT233FieldElement)b.RawXCoord;

            if (X1.IsZero)
            {
                if (X2.IsZero)
                    return curve.Infinity;

                return b.Add(this);
            }

            SecT233FieldElement L1 = (SecT233FieldElement)this.RawYCoord, Z1 = (SecT233FieldElement)this.RawZCoords[0];
            SecT233FieldElement L2 = (SecT233FieldElement)b.RawYCoord, Z2 = (SecT233FieldElement)b.RawZCoords[0];

            ulong[] tt0 = Nat256.CreateExt64();
            ulong[] t1 = Nat256.Create64();
            ulong[] t2 = Nat256.Create64();
            ulong[] t3 = Nat256.Create64();

            bool Z1IsOne = Z1.IsOne;
            if (Z1IsOne)
            {
                Nat256.Copy64(X2.x, t1);                    // U2
                Nat256.Copy64(L2.x, t2);                    // S2
            }
            else
            {
                SecT233Field.Multiply(X2.x, Z1.x, t1);      // U2
                SecT233Field.Multiply(L2.x, Z1.x, t2);      // S2
            }

            bool Z2IsOne = Z2.IsOne;
            if (Z2IsOne)
            {
                Nat256.Copy64(X1.x, t3);                    // U1
                Nat256.Copy64(L1.x, tt0);                   // S1
            }
            else
            {
                SecT233Field.Multiply(X1.x, Z2.x, t3);      // U1
                SecT233Field.Multiply(L1.x, Z2.x, tt0);     // S1
            }

            SecT233Field.AddTo(tt0, t2);                    // A
            SecT233Field.Add(t3, t1, tt0);                  // B

            if (Nat256.IsZero64(tt0))
            {
                if (Nat256.IsZero64(t2))
                    return Twice();

                return curve.Infinity;
            }

            if (X2.IsZero)
            {
                // TODO This can probably be optimized quite a bit
                ECPoint p = this.Normalize();
                X1 = (SecT233FieldElement)p.XCoord;
                ECFieldElement Y1 = p.YCoord;

                ECFieldElement Y2 = L2;
                ECFieldElement L = Y1.Add(Y2).Divide(X1);

                ECFieldElement X3 = L.Square().Add(L).Add(X1);
                if (X3.IsZero)
                    return new SecT233K1Point(curve, X3, curve.B);

                ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
                ECFieldElement L3 = Y3.Divide(X3).Add(X3);
                ECFieldElement Z3 = curve.FromBigInteger(BigInteger.One);

                return new SecT233K1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
            }

            SecT233Field.Square(tt0, tt0);

            SecT233Field.Multiply(t3, t2, t3);      // AU1
            SecT233Field.Multiply(t1, t2, t1);      // AU2

            ulong[] _X3 = t3;
            SecT233Field.Multiply(_X3, t1, _X3);
            if (Nat256.IsZero64(_X3))
                return new SecT233K1Point(curve, new SecT233FieldElement(_X3), curve.B);

            ulong[] _Z3 = t2;
            SecT233Field.Multiply(_Z3, tt0, _Z3);   // ABZ2
            if (!Z2IsOne)
            {
                SecT233Field.Multiply(_Z3, Z2.x, _Z3);
            }

            ulong[] _L3 = t1;
            SecT233Field.AddTo(tt0, _L3);
            SecT233Field.SquareExt(_L3, tt0);
            SecT233Field.Add(L1.x, Z1.x, _L3);
            SecT233Field.MultiplyAddToExt(_Z3, _L3, tt0);
            SecT233Field.Reduce(tt0, _L3);

            if (!Z1IsOne)
            {
                SecT233Field.Multiply(_Z3, Z1.x, _Z3);
            }

            return new SecT233K1Point(curve, new SecT233FieldElement(_X3), new SecT233FieldElement(_L3),
                new ECFieldElement[]{ new SecT233FieldElement(_Z3) });
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
            ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.Square();
            ECFieldElement T;
            if (Z1IsOne)
            {
                T = L1.Square().Add(L1);
            }
            else
            {
                T = L1.Add(Z1).Multiply(L1);
            }

            if (T.IsZero)
            {
                return new SecT233K1Point(curve, T, curve.B);
            }

            ECFieldElement X3 = T.Square();
            ECFieldElement Z3 = Z1IsOne ? T : T.Multiply(Z1Sq);

            ECFieldElement t1 = L1.Add(X1).Square();
            ECFieldElement t2 = Z1IsOne ? Z1 : Z1Sq.Square();
            ECFieldElement L3 = t1.Add(T).Add(Z1Sq).Multiply(t1).Add(t2).Add(X3).Add(Z3);

            return new SecT233K1Point(curve, X3, L3, new ECFieldElement[] { Z3 });
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

            ECFieldElement T = L1Sq.Add(L1Z1);
            ECFieldElement L2plus1 = L2.AddOne();
            ECFieldElement A = L2plus1.Multiply(Z1Sq).Add(L1Sq).MultiplyPlusProduct(T, X1Sq, Z1Sq);
            ECFieldElement X2Z1Sq = X2.Multiply(Z1Sq);
            ECFieldElement B = X2Z1Sq.Add(T).Square();

            if (B.IsZero)
            {
                if (A.IsZero)
                {
                    return b.Twice();
                }

                return curve.Infinity;
            }

            if (A.IsZero)
            {
                return new SecT233K1Point(curve, A, curve.B);
            }

            ECFieldElement X3 = A.Square().Multiply(X2Z1Sq);
            ECFieldElement Z3 = A.Multiply(B).Multiply(Z1Sq);
            ECFieldElement L3 = A.Add(B).Square().MultiplyPlusProduct(T, L2plus1, Z3);

            return new SecT233K1Point(curve, X3, L3, new ECFieldElement[] { Z3 });
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
            return new SecT233K1Point(Curve, X, L.Add(Z), new ECFieldElement[] { Z });
        }
    }
}
