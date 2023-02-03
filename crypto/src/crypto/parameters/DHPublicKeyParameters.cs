using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.Raw;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Parameters
{
    public class DHPublicKeyParameters
		: DHKeyParameters
    {
        private static BigInteger Validate(BigInteger y, DHParameters dhParams)
        {
            if (y == null)
                throw new ArgumentNullException(nameof(y));

            BigInteger p = dhParams.P;

            // TLS check
            if (y.CompareTo(BigInteger.Two) < 0 || y.CompareTo(p.Subtract(BigInteger.Two)) > 0)
                throw new ArgumentException("invalid DH public key", nameof(y));

            BigInteger q = dhParams.Q;

            // We can't validate without Q.
            if (q == null)
                return y;

            if (p.TestBit(0)
                && p.BitLength - 1 == q.BitLength
                && p.ShiftRight(1).Equals(q))
            {
                // Safe prime case
                if (1 == Legendre(y, p))
                    return y;
            }
            else
            {
                if (BigInteger.One.Equals(y.ModPow(q, p)))
                    return y;
            }

            throw new ArgumentException("value does not appear to be in correct group", nameof(y));
        }

        private readonly BigInteger m_y;

		public DHPublicKeyParameters(BigInteger y, DHParameters	parameters)
			: base(false, parameters)
        {
			m_y = Validate(y, parameters);
        }

		public DHPublicKeyParameters(BigInteger y, DHParameters parameters, DerObjectIdentifier	algorithmOid)
			: base(false, parameters, algorithmOid)
        {
            m_y = Validate(y, parameters);
        }

        public virtual BigInteger Y => m_y;

		public override bool Equals(object obj)
        {
			if (obj == this)
				return true;

            if (!(obj is DHPublicKeyParameters other))
				return false;

			return Equals(other);
        }

		protected bool Equals(DHPublicKeyParameters other)
		{
			return m_y.Equals(other.m_y) && base.Equals(other);
		}

		public override int GetHashCode()
        {
            return m_y.GetHashCode() ^ base.GetHashCode();
        }

        private static int Legendre(BigInteger a, BigInteger b)
        {
            //int r = 0, bits = b.IntValue;

            //for (;;)
            //{
            //    int lowestSetBit = a.GetLowestSetBit();
            //    a = a.ShiftRight(lowestSetBit);
            //    r ^= (bits ^ (bits >> 1)) & (lowestSetBit << 1);

            //    int cmp = a.CompareTo(b);
            //    if (cmp == 0)
            //        break;

            //    if (cmp < 0)
            //    {
            //        BigInteger t = a; a = b; b = t;

            //        int oldBits = bits;
            //        bits = b.IntValue;
            //        r ^= oldBits & bits;
            //    }

            //    a = a.Subtract(b);
            //}

            //return BigInteger.One.Equals(b) ? (1 - (r & 2)) : 0;

            int bitLength = b.BitLength;
            int len = Nat.GetLengthForBits(bitLength);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<uint> A = len <= 64
                ? stackalloc uint[len]
                : new uint[len];
            Nat.FromBigInteger(bitLength, a, A);
            Span<uint> B = len <= 64
                ? stackalloc uint[len]
                : new uint[len];
            Nat.FromBigInteger(bitLength, b, B);
#else
            uint[] A = Nat.FromBigInteger(bitLength, a);
            uint[] B = Nat.FromBigInteger(bitLength, b);
#endif

            int r = 0;

            for (;;)
            {
                while (A[0] == 0)
                {
                    Nat.ShiftDownWord(len, A, 0);
                }

                int shift = Integers.NumberOfTrailingZeros((int)A[0]);
                if (shift > 0)
                {
                    Nat.ShiftDownBits(len, A, shift, 0);
                    int bits = (int)B[0];
                    r ^= (bits ^ (bits >> 1)) & (shift << 1);
                }

                int cmp = Nat.Compare(len, A, B);
                if (cmp == 0)
                    break;

                if (cmp < 0)
                {
                    r ^= (int)(A[0] & B[0]);
                    var t = A; A = B; B = t;
                }

                while (A[len - 1] == 0)
                {
                    len = len - 1;
                }

                Nat.Sub(len, A, B, A);
            }

            return Nat.IsOne(len, B) ? (1 - (r & 2)) : 0;
        }
    }
}
