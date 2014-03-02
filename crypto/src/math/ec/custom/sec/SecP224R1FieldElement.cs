using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP224R1FieldElement
        : ECFieldElement
    {
        public static readonly BigInteger Q = SecP224R1Curve.q;

        protected internal readonly uint[] x;

        public SecP224R1FieldElement(BigInteger x)
        {
            if (x == null || x.SignValue < 0 || x.CompareTo(Q) >= 0)
                throw new ArgumentException("value invalid for SecP224R1FieldElement", "x");

            this.x = SecP224R1Field.FromBigInteger(x);
        }

        public SecP224R1FieldElement()
        {
            this.x = Nat224.Create();
        }

        protected internal SecP224R1FieldElement(uint[] x)
        {
            this.x = x;
        }

        public override bool IsZero
        {
            get { return Nat224.IsZero(x); }
        }

        public override bool IsOne
        {
            get { return Nat224.IsOne(x); }
        }

        public override bool TestBitZero()
        {
            return Nat224.GetBit(x, 0) == 1;
        }

        public override BigInteger ToBigInteger()
        {
            return Nat224.ToBigInteger(x);
        }

        public override string FieldName
        {
            get { return "SecP224R1Field"; }
        }

        public override int FieldSize
        {
            get { return Q.BitLength; }
        }

        public override ECFieldElement Add(ECFieldElement b)
        {
            uint[] z = Nat224.Create();
            SecP224R1Field.Add(x, ((SecP224R1FieldElement)b).x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement AddOne()
        {
            uint[] z = Nat224.Create();
            SecP224R1Field.AddOne(x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement Subtract(ECFieldElement b)
        {
            uint[] z = Nat224.Create();
            SecP224R1Field.Subtract(x, ((SecP224R1FieldElement)b).x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement Multiply(ECFieldElement b)
        {
            uint[] z = Nat224.Create();
            SecP224R1Field.Multiply(x, ((SecP224R1FieldElement)b).x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement Divide(ECFieldElement b)
        {
            //return Multiply(b.Invert());
            uint[] z = Nat224.Create();
            Mod.Invert(SecP224R1Field.P, ((SecP224R1FieldElement)b).x, z);
            SecP224R1Field.Multiply(z, x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement Negate()
        {
            uint[] z = Nat224.Create();
            SecP224R1Field.Negate(x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement Square()
        {
            uint[] z = Nat224.Create();
            SecP224R1Field.Square(x, z);
            return new SecP224R1FieldElement(z);
        }

        public override ECFieldElement Invert()
        {
            //return new SecP224R1FieldElement(ToBigInteger().ModInverse(Q));
            uint[] z = Nat224.Create();
            Mod.Invert(SecP224R1Field.P, x, z);
            return new SecP224R1FieldElement(z);
        }

        /**
         * return a sqrt root - the routine verifies that the calculation returns the right value - if
         * none exists it returns null.
         */
        public override ECFieldElement Sqrt()
        {
            uint[] c = this.x;
            if (Nat224.IsZero(c) || Nat224.IsOne(c))
                return this;

            uint[] nc = Nat224.Create();
            SecP224R1Field.Negate(c, nc);

            uint[] r = Mod.Random(SecP224R1Field.P);

            for (;;)
            {
                uint[] d1 = Nat224.Create();
                Nat224.Copy(r, d1);
                uint[] e1 = Nat224.Create();
                e1[0] = 1;
                uint[] f1 = Nat224.Create();
                RP(nc, d1, e1, f1);

                uint[] d0 = Nat224.Create();
                uint[] e0 = Nat224.Create();

                for (int k = 1; k < 96; ++k)
                {
                    Nat224.Copy(d1, d0);
                    Nat224.Copy(e1, e0);

                    RS(d1, e1, f1);

                    if (Nat224.IsZero(d1))
                    {
                        Mod.Invert(SecP224R1Field.P, e0, f1);
                        SecP224R1Field.Multiply(f1, d0, f1);

                        SecP224R1Field.Square(f1, d1);

                        return Nat224.Eq(c, d1) ? new SecP224R1FieldElement(f1) : null;
                    }
                }

                // Avoid any possible infinite loop due to a bad random number generator
                SecP224R1Field.AddOne(r, r);
            }
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as SecP224R1FieldElement);
        }

        public override bool Equals(ECFieldElement other)
        {
            return Equals(other as SecP224R1FieldElement);
        }

        public virtual bool Equals(SecP224R1FieldElement other)
        {
            if (this == other)
                return true;
            if (null == other)
                return false;
            return Nat224.Eq(x, other.x);
        }

        public override int GetHashCode()
        {
            return Q.GetHashCode() ^ Arrays.GetHashCode(x, 0, 7);
        }

        private static void RM(uint[] nc, uint[] d0, uint[] e0, uint[] d1, uint[] e1, uint[] f1)
        {
            uint[] t = Nat224.Create();
            SecP224R1Field.Multiply(e1, e0, t);
            SecP224R1Field.Multiply(t, nc, t);
            SecP224R1Field.Multiply(d1, d0, f1);
            SecP224R1Field.Add(f1, t, f1);
            SecP224R1Field.Multiply(d1, e0, t);
            Nat224.Copy(f1, d1);
            SecP224R1Field.Multiply(e1, d0, e1);
            SecP224R1Field.Add(e1, t, e1);
            SecP224R1Field.Square(e1, f1);
            SecP224R1Field.Multiply(f1, nc, f1);
        }

        private static void RP(uint[] nc, uint[] d1, uint[] e1, uint[] f1)
        {
            Nat224.Copy(nc, f1);

            uint[] d0 = Nat224.Create();
            uint[] e0 = Nat224.Create();

            for (int i = 0; i < 7; ++i)
            {
                Nat224.Copy(d1, d0);
                Nat224.Copy(e1, e0);

                int j = 1 << i;
                while (--j >= 0)
                {
                    RS(d1, e1, f1);
                }

                RM(nc, d0, e0, d1, e1, f1);
            }
        }

        private static void RS(uint[] d, uint[] e, uint[] f)
        {
            SecP224R1Field.Multiply(e, d, e);
            uint[] t = Nat224.Create();
            SecP224R1Field.Square(d, t);
            SecP224R1Field.Add(f, t, d);
            SecP224R1Field.Twice(e, e);
            SecP224R1Field.Multiply(f, t, f);
            uint c = Nat.ShiftUpBits(7, f, 2, 0);
            SecP224R1Field.Reduce32(c, f);
        }
    }
}
