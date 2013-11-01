using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerEnumerated
        : Asn1Object
    {
        private readonly byte[] bytes;

		/**
         * return an integer from the passed in object
         *
         * @exception ArgumentException if the object cannot be converted.
         */
        public static DerEnumerated GetInstance(
            object obj)
        {
            if (obj == null || obj is DerEnumerated)
            {
                return (DerEnumerated)obj;
            }

            throw new ArgumentException("illegal object in GetInstance: " + obj.GetType().Name);
        }

        /**
         * return an Enumerated from a tagged object.
         *
         * @param obj the tagged object holding the object we want
         * @param explicitly true if the object is meant to be explicitly
         *              tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot
         *               be converted.
         */
        public static DerEnumerated GetInstance(
            Asn1TaggedObject	obj,
            bool				isExplicit)
        {
			Asn1Object o = obj.GetObject();

			if (isExplicit || o is DerEnumerated)
			{
				return GetInstance(o);
			}

			return new DerEnumerated(((Asn1OctetString)o).GetOctets());
        }

        public DerEnumerated(
            int val)
        {
            bytes = BigInteger.ValueOf(val).ToByteArray();
        }

        public DerEnumerated(
            BigInteger val)
        {
            bytes = val.ToByteArray();
        }

        public DerEnumerated(
            byte[]   bytes)
        {
            this.bytes = Arrays.Clone(bytes);
        }

        public BigInteger Value
        {
            get
            {
                return new BigInteger(bytes);
            }
        }

		internal override void Encode(
            DerOutputStream derOut)
        {
            derOut.WriteEncoded(Asn1Tags.Enumerated, bytes);
        }

		protected override bool Asn1Equals(
			Asn1Object asn1Object)
        {
			DerEnumerated other = asn1Object as DerEnumerated;

			if (other == null)
				return false;

			return Arrays.AreEqual(this.bytes, other.bytes);
        }

		protected override int Asn1GetHashCode()
		{
			return Arrays.GetHashCode(bytes);
        }
    }
}
