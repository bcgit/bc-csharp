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
            ECFieldElement root = new FpFieldElement(Q, ToBigInteger()).Sqrt();
            return root == null ? null : new SecP224R1FieldElement(root.ToBigInteger());
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
            return Arrays.AreEqual(x, other.x);
        }

        public override int GetHashCode()
        {
            return Q.GetHashCode() ^ Arrays.GetHashCode(x);
        }
    }
}
