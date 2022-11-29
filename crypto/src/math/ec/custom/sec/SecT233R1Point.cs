using System;

using Org.BouncyCastle.Math.Raw;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecT233R1Point
        : AbstractF2mPoint
    {
        internal SecT233R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
            : base(curve, x, y)
        {
        }

        internal SecT233R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
            : base(curve, x, y, zs)
        {
        }

        protected override ECPoint Detach()
        {
            return new SecT233R1Point(null, AffineXCoord, AffineYCoord);
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

            ECFieldElement X1 = this.RawXCoord;
            ECFieldElement X2 = b.RawXCoord;

            if (X1.IsZero)
            {
                if (X2.IsZero)
                    return curve.Infinity;

                return b.Add(this);
            }

            ECFieldElement L1 = this.RawYCoord, Z1 = this.RawZCoords[0];
            ECFieldElement L2 = b.RawYCoord, Z2 = b.RawZCoords[0];

            bool Z1IsOne = Z1.IsOne;
            ECFieldElement U2 = X2, S2 = L2;
            if (!Z1IsOne)
            {
                U2 = U2.Multiply(Z1);
                S2 = S2.Multiply(Z1);
            }

            bool Z2IsOne = Z2.IsOne;
            ECFieldElement U1 = X1, S1 = L1;
            if (!Z2IsOne)
            {
                U1 = U1.Multiply(Z2);
                S1 = S1.Multiply(Z2);
            }

            ECFieldElement A = S1.Add(S2);
            ECFieldElement B = U1.Add(U2);

            if (B.IsZero)
            {
                if (A.IsZero)
                    return Twice();

                return curve.Infinity;
            }

            ECFieldElement X3, L3, Z3;
            if (X2.IsZero)
            {
                // TODO This can probably be optimized quite a bit
                ECPoint p = this.Normalize();
                X1 = p.XCoord;
                ECFieldElement Y1 = p.YCoord;

                ECFieldElement Y2 = L2;
                ECFieldElement L = Y1.Add(Y2).Divide(X1);

                X3 = L.Square().Add(L).Add(X1).AddOne();
                if (X3.IsZero)
                {
                    return new SecT233R1Point(curve, X3, curve.B.Sqrt());
                }

                ECFieldElement Y3 = L.Multiply(X1.Add(X3)).Add(X3).Add(Y1);
                L3 = Y3.Divide(X3).Add(X3);
                Z3 = curve.FromBigInteger(BigInteger.One);
            }
            else
            {
                B = B.Square();

                ECFieldElement AU1 = A.Multiply(U1);
                ECFieldElement AU2 = A.Multiply(U2);

                X3 = AU1.Multiply(AU2);
                if (X3.IsZero)
                {
                    return new SecT233R1Point(curve, X3, curve.B.Sqrt());
                }

                ECFieldElement ABZ2 = A.Multiply(B);
                if (!Z2IsOne)
                {
                    ABZ2 = ABZ2.Multiply(Z2);
                }

                L3 = AU2.Add(B).SquarePlusProduct(ABZ2, L1.Add(Z1));

                Z3 = ABZ2;
                if (!Z1IsOne)
                {
                    Z3 = Z3.Multiply(Z1);
                }
            }

            return new SecT233R1Point(curve, X3, L3, new ECFieldElement[]{ Z3 });
        }

        public override ECPoint Twice()
        {
            if (this.IsInfinity)
                return this;

            ECCurve curve = this.Curve;

            SecT233FieldElement X1 = (SecT233FieldElement)this.RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is its own additive inverse
                return curve.Infinity;
            }

            SecT233FieldElement L1 = (SecT233FieldElement)this.RawYCoord, Z1 = (SecT233FieldElement)this.RawZCoords[0];

            ulong[] tt0 = Nat256.CreateExt64();
            ulong[] _X3 = Nat256.Create64();
            ulong[] _L3 = Nat256.Create64();
            ulong[] _Z3 = Nat256.Create64();

            bool Z1IsOne = Z1.IsOne;
            if (Z1IsOne)
            {
                SecT233Field.Square(L1.x, _Z3);
                SecT233Field.AddBothTo(L1.x, Z1.x, _Z3);

                if (Nat256.IsZero64(_Z3))
                    return new SecT233R1Point(curve, new SecT233FieldElement(_Z3), curve.B.Sqrt());

                SecT233Field.Square(_Z3, _X3);

                SecT233Field.SquareExt(X1.x, tt0);
                SecT233Field.MultiplyAddToExt(_Z3, L1.x, tt0);
            }
            else
            {
                ulong[] t1 = Nat256.Create64();
                ulong[] t2 = Nat256.Create64();

                SecT233Field.Multiply(L1.x, Z1.x, t1);      // L1Z1
                SecT233Field.Square(Z1.x, tt0);             // Z1Sq

                SecT233Field.Square(L1.x, t2);
                SecT233Field.AddBothTo(t1, tt0, t2);        // T

                if (Nat256.IsZero64(t2))
                    return new SecT233R1Point(curve, new SecT233FieldElement(t2), curve.B.Sqrt());

                SecT233Field.Square(t2, _X3);
                SecT233Field.Multiply(t2, tt0, _Z3);
                SecT233Field.Multiply(X1.x, Z1.x, tt0);     // X1Z1

                SecT233Field.SquareExt(tt0, tt0);
                SecT233Field.MultiplyAddToExt(t2, t1, tt0);
            }

            SecT233Field.Reduce(tt0, _L3);
            SecT233Field.AddBothTo(_X3, _Z3, _L3);

            return new SecT233R1Point(curve, new SecT233FieldElement(_X3), new SecT233FieldElement(_L3),
                new ECFieldElement[]{ new SecT233FieldElement(_Z3) });
        }

        public override ECPoint TwicePlus(ECPoint b)
        {
            if (this.IsInfinity)
                return b;
            if (b.IsInfinity)
                return Twice();

            ECCurve curve = this.Curve;

            SecT233FieldElement X1 = (SecT233FieldElement)this.RawXCoord;
            if (X1.IsZero)
            {
                // A point with X == 0 is its own additive inverse
                return b;
            }

            SecT233FieldElement X2 = (SecT233FieldElement)b.RawXCoord, Z2 = (SecT233FieldElement)b.RawZCoords[0];
            if (X2.IsZero || !Z2.IsOne)
            {
                return Twice().Add(b);
            }

            SecT233FieldElement L1 = (SecT233FieldElement)this.RawYCoord, Z1 = (SecT233FieldElement)this.RawZCoords[0];
            SecT233FieldElement L2 = (SecT233FieldElement)b.RawYCoord;

            ulong[] tt0 = Nat256.CreateExt64();
            ulong[] t1 = Nat256.Create64();
            ulong[] t2 = Nat256.Create64();
            ulong[] t3 = Nat256.Create64();
            ulong[] t4 = Nat256.Create64();
            ulong[] t5 = Nat256.Create64();

            SecT233Field.Square(X1.x, t1);              // X1Sq
            SecT233Field.Square(L1.x, t2);              // L1Sq
            SecT233Field.Square(Z1.x, t3);              // Z1Sq
            SecT233Field.Multiply(L1.x, Z1.x, t4);      // L1Z1

            SecT233Field.AddBothTo(t2, t3, t4);         // T

            SecT233Field.MultiplyExt(t1, t3, tt0);
            SecT233Field.Multiply(L2.x, t3, t1);
            SecT233Field.AddTo(t2, t1);
            SecT233Field.MultiplyAddToExt(t4, t1, tt0);
            SecT233Field.Reduce(tt0, t1);               // A

            SecT233Field.Multiply(X2.x, t3, t2);        // X2Z1Sq
            SecT233Field.Add(t4, t2, t5);
            SecT233Field.Square(t5, t5);                // B

            if (Nat256.IsZero64(t5))
            {
                if (Nat256.IsZero64(t1))
                    return b.Twice();

                return curve.Infinity;
            }

            if (Nat256.IsZero64(t1))
                return new SecT233R1Point(curve, new SecT233FieldElement(t1), curve.B.Sqrt());

            ulong[] _X3 = t2;
            SecT233Field.Square(t1, tt0);
            SecT233Field.Multiply(_X3, tt0, _X3);

            ulong[] _Z3 = t3;
            SecT233Field.Multiply(_Z3, t1, _Z3);
            SecT233Field.Multiply(_Z3, t5, _Z3);

            ulong[] _L3 = t1;
            SecT233Field.AddTo(t5, _L3);
            SecT233Field.Square(_L3, _L3);
            SecT233Field.MultiplyExt(_L3, t4, tt0);
            SecT233Field.MultiplyAddToExt(L2.x, _Z3, tt0);
            SecT233Field.Reduce(tt0, _L3);
            SecT233Field.AddTo(_Z3, _L3);

            return new SecT233R1Point(curve, new SecT233FieldElement(_X3), new SecT233FieldElement(_L3),
                new ECFieldElement[]{ new SecT233FieldElement(_Z3) });
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
            return new SecT233R1Point(Curve, X, L.Add(Z), new ECFieldElement[]{ Z });
        }
    }
}
