using System;

using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Math.EC.Custom.Djb
{
    internal class Curve25519
        : AbstractFpCurve
    {
        public static readonly BigInteger q = Curve25519FieldElement.Q;

        private static readonly BigInteger C_a = new BigInteger(1, Hex.DecodeStrict("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144"));
        private static readonly BigInteger C_b = new BigInteger(1, Hex.DecodeStrict("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864"));

        private const int CURVE25519_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;
        private const int CURVE25519_FE_INTS = 8;
        private static readonly ECFieldElement[] CURVE25519_AFFINE_ZS = new ECFieldElement[] {
            new Curve25519FieldElement(BigInteger.One), new Curve25519FieldElement(C_a) }; 
        protected readonly Curve25519Point m_infinity;

        public Curve25519()
            : base(q)
        {
            this.m_infinity = new Curve25519Point(this, null, null);

            this.m_a = FromBigInteger(C_a);
            this.m_b = FromBigInteger(C_b);
            this.m_order = new BigInteger(1, Hex.DecodeStrict("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
            this.m_cofactor = BigInteger.ValueOf(8);
            this.m_coord = CURVE25519_DEFAULT_COORDS;
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

        public override ECLookupTable CreateCacheSafeLookupTable(ECPoint[] points, int off, int len)
        {
            uint[] table = new uint[len * CURVE25519_FE_INTS * 2];
            {
                int pos = 0;
                for (int i = 0; i < len; ++i)
                {
                    ECPoint p = points[off + i];
                    Nat256.Copy(((Curve25519FieldElement)p.RawXCoord).x, 0, table, pos); pos += CURVE25519_FE_INTS;
                    Nat256.Copy(((Curve25519FieldElement)p.RawYCoord).x, 0, table, pos); pos += CURVE25519_FE_INTS;
                }
            }

            return new Curve25519LookupTable(this, table, len);
        }

        public override ECFieldElement RandomFieldElement(SecureRandom r)
        {
            uint[] x = Nat256.Create();
            Curve25519Field.Random(r, x);
            return new Curve25519FieldElement(x);
        }

        public override ECFieldElement RandomFieldElementMult(SecureRandom r)
        {
            uint[] x = Nat256.Create();
            Curve25519Field.RandomMult(r, x);
            return new Curve25519FieldElement(x);
        }

        private class Curve25519LookupTable
            : AbstractECLookupTable
        {
            private readonly Curve25519 m_outer;
            private readonly uint[] m_table;
            private readonly int m_size;

            internal Curve25519LookupTable(Curve25519 outer, uint[] table, int size)
            {
                this.m_outer = outer;
                this.m_table = table;
                this.m_size = size;
            }

            public override int Size
            {
                get { return m_size; }
            }

            public override ECPoint Lookup(int index)
            {
                uint[] x = Nat256.Create(), y = Nat256.Create();
                int pos = 0;

                for (int i = 0; i < m_size; ++i)
                {
                    uint MASK = (uint)(((i ^ index) - 1) >> 31);

                    for (int j = 0; j < CURVE25519_FE_INTS; ++j)
                    {
                        x[j] ^= m_table[pos + j] & MASK;
                        y[j] ^= m_table[pos + CURVE25519_FE_INTS + j] & MASK;
                    }

                    pos += (CURVE25519_FE_INTS * 2);
                }

                return CreatePoint(x, y);
            }

            public override ECPoint LookupVar(int index)
            {
                uint[] x = Nat256.Create(), y = Nat256.Create();
                int pos = index * CURVE25519_FE_INTS * 2;

                for (int j = 0; j < CURVE25519_FE_INTS; ++j)
                {
                    x[j] = m_table[pos + j];
                    y[j] = m_table[pos + CURVE25519_FE_INTS + j];
                }

                return CreatePoint(x, y);
            }

            private ECPoint CreatePoint(uint[] x, uint[] y)
            {
                return m_outer.CreateRawPoint(new Curve25519FieldElement(x), new Curve25519FieldElement(y), CURVE25519_AFFINE_ZS, false);
            }
        }
    }
}
