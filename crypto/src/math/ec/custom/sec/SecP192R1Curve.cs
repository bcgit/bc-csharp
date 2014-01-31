using System;

using Org.BouncyCastle.Math.Field;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Math.EC.Custom.Sec
{
    internal class SecP192R1Curve
        : ECCurve
    {
        public static readonly BigInteger q = new BigInteger(1,
            Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"));

        private const int SecP192R1_DEFAULT_COORDS = COORD_JACOBIAN;

        protected readonly SecP192R1Point m_infinity;

        public SecP192R1Curve()
            : base(FiniteFields.GetPrimeField(q))
        {
            this.m_infinity = new SecP192R1Point(this, null, null);

            this.m_a = FromBigInteger(new BigInteger(1,
                Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC")));
            this.m_b = FromBigInteger(new BigInteger(1,
                Hex.Decode("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1")));
            this.m_order = new BigInteger(1, Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"));
            this.m_cofactor = BigInteger.One;

            this.m_coord = SecP192R1_DEFAULT_COORDS;
        }

        protected override ECCurve CloneCurve()
        {
            return new SecP192R1Curve();
        }

        public override bool SupportsCoordinateSystem(int coord)
        {
            switch (coord)
            {
            case COORD_JACOBIAN:
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
            return new SecP192R1FieldElement(x);
        }

        protected internal override ECPoint CreateRawPoint(ECFieldElement x, ECFieldElement y, bool withCompression)
        {
            return new SecP192R1Point(this, x, y, withCompression);
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

            return new SecP192R1Point(this, x, beta, true);
        }
    }
}
