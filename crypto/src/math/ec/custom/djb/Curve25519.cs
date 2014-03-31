using System;

using Org.BouncyCastle.Math.EC.Custom.Sec;
using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Math.EC.Custom.Djb
{
    internal class Curve25519
        :   ECCurve
    {
        public static readonly BigInteger q = Nat256.ToBigInteger(Curve25519Field.P);

        private const int Curve25519_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;

        protected readonly Curve25519Point m_infinity;

        public Curve25519()
            :   base(FiniteFields.GetPrimeField(q))
        {
            this.m_infinity = new Curve25519Point(this, null, null);

            this.m_a = FromBigInteger(new BigInteger(1,
                Hex.Decode("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144")));
            this.m_b = FromBigInteger(new BigInteger(1,
                Hex.Decode("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864")));
            this.m_order = new BigInteger(1, Hex.Decode("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
            this.m_cofactor = BigInteger.ValueOf(8);
            this.m_coord = Curve25519_DEFAULT_COORDS;
        }

        protected override ECCurve CloneCurve()
        {
            return new Curve25519();
        }

        public override bool SupportsCoordinateSystem(int coord)
        {
            switch (coord)
            {
            case COORD_JACOBIAN_MODIFIED:
                return true;
            default:
                return false;
            }
        }

        public virtual BigInteger Q
        {
            get { return q; }
        }

        public override ECPoint Infinity
        {
            get { return m_infinity; }
        }

        public override int FieldSize
        {
            get { return q.BitLength; }
        }

        public override ECFieldElement FromBigInteger(BigInteger x)
        {
            return new Curve25519FieldElement(x);
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
        {
            return new Curve25519Point(this, x, y, withCompression);
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, bool withCompression)
        {
            return new Curve25519Point(this, x, y, zs, withCompression);
        }

        protected override ECPoint DecompressPoint(int yTilde, BigInteger X1)
        {
            ECFieldElement x = FromBigInteger(X1);
            ECFieldElement alpha = x.Square().Add(A).Multiply(x).Add(B);
            ECFieldElement beta = alpha.Sqrt();

            //
            // if we can't find a sqrt we haven't got a point on the
            // curve - run!
            //
            if (beta == null)
                throw new ArithmeticException("Invalid point compression");

            if (beta.TestBitZero() != (yTilde == 1))
            {
                // Use the other root
                beta = beta.Negate();
            }

            return new Curve25519Point(this, x, beta, true);
        }
    }
}
