using System;
using System.Diagnostics;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    public class SecP256R1FieldElement
        : ECFieldElement
    {
        public static readonly BigInteger Q = SecP256R1Curve.q;

        protected internal readonly uint[] x;

        public SecP256R1FieldElement(BigInteger x)
        {
            if (x == null || x.SignValue < 0 || x.CompareTo(Q) >= 0)
                throw new ArgumentException("value invalid for SecP256R1FieldElement", "x");

            this.x = SecP256R1Field.FromBigInteger(x);
        }

        public SecP256R1FieldElement()
        {
            this.x = Nat256.Create();
        }

        protected internal SecP256R1FieldElement(uint[] x)
        {
            this.x = x;
        }

        public override bool IsZero
        {
            get { return Nat256.IsZero(x); }
        }

        public override bool IsOne
        {
            get { return Nat256.IsOne(x); }
        }

        public override bool TestBitZero()
        {
            return Nat256.GetBit(x, 0) == 1;
        }

        public override BigInteger ToBigInteger()
        {
            return Nat256.ToBigInteger(x);
        }

        public override string FieldName
        {
            get { return "SecP256R1Field"; }
        }

        public override int FieldSize
        {
            get { return Q.BitLength; }
        }

        public override ECFieldElement Add(ECFieldElement b)
        {
            uint[] z = Nat256.Create();
            SecP256R1Field.Add(x, ((SecP256R1FieldElement)b).x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement AddOne()
        {
            uint[] z = Nat256.Create();
            SecP256R1Field.AddOne(x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement Subtract(ECFieldElement b)
        {
            uint[] z = Nat256.Create();
            SecP256R1Field.Subtract(x, ((SecP256R1FieldElement)b).x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement Multiply(ECFieldElement b)
        {
            uint[] z = Nat256.Create();
            SecP256R1Field.Multiply(x, ((SecP256R1FieldElement)b).x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement Divide(ECFieldElement b)
        {
            //return Multiply(b.Invert());
            uint[] z = Nat256.Create();
            Mod.Invert(SecP256R1Field.P, ((SecP256R1FieldElement)b).x, z);
            SecP256R1Field.Multiply(z, x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement Negate()
        {
            uint[] z = Nat256.Create();
            SecP256R1Field.Negate(x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement Square()
        {
            uint[] z = Nat256.Create();
            SecP256R1Field.Square(x, z);
            return new SecP256R1FieldElement(z);
        }

        public override ECFieldElement Invert()
        {
            //return new SecP256R1FieldElement(ToBigInteger().ModInverse(Q));
            uint[] z = Nat256.Create();
            Mod.Invert(SecP256R1Field.P, x, z);
            return new SecP256R1FieldElement(z);
        }

        // D.1.4 91
        /**
         * return a sqrt root - the routine verifies that the calculation returns the right value - if
         * none exists it returns null.
         */
        public override ECFieldElement Sqrt()
        {
            ECFieldElement root = new FpFieldElement(Q, ToBigInteger()).Sqrt();
            return root == null ? null : new SecP256R1FieldElement(root.ToBigInteger());
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as SecP256R1FieldElement);
        }

        public override bool Equals(ECFieldElement other)
        {
            return Equals(other as SecP256R1FieldElement);
        }

        public virtual bool Equals(SecP256R1FieldElement other)
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
