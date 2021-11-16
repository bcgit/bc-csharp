using System;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1OctetString
        : Asn1Object, Asn1OctetStringParser
    {
        internal static readonly byte[] EmptyOctets = new byte[0];

        /**
         * return an Octet string from the given object.
         *
         * @param obj the object we want converted.
         * @exception ArgumentException if the object cannot be converted.
         */
        public static Asn1OctetString GetInstance(object obj)
        {
            if (obj == null || obj is Asn1OctetString)
            {
                return (Asn1OctetString)obj;
            }
            //else if (obj is Asn1OctetStringParser)
            else if (obj is IAsn1Convertible)
            {
                Asn1Object asn1Object = ((IAsn1Convertible)obj).ToAsn1Object();
                if (asn1Object is Asn1OctetString)
                {
                    return (Asn1OctetString)asn1Object;
                }
            }
            else if (obj is byte[])
            {
                try
                {
                    return GetInstance(FromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct OCTET STRING from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        /**
         * return an Octet string from a tagged object.
         *
         * @param obj the tagged object holding the object we want.
         * @param explicitly true if the object is meant to be explicitly
         *              tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot
         *              be converted.
         */
        public static Asn1OctetString GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            if (declaredExplicit)
            {
                if (!taggedObject.IsExplicit())
                    throw new ArgumentException("object implicit - explicit expected.");

                return GetInstance(taggedObject.GetObject());
            }

            Asn1Object baseObject = taggedObject.GetObject();

            // If parsed as explicit though declared implicit, it should have been a set of one
            if (taggedObject.IsExplicit())
            {
                Asn1OctetString singleSegment = GetInstance(baseObject);

                if (taggedObject is BerTaggedObject)
                    return new BerOctetString(new Asn1OctetString[]{ singleSegment });

                return singleSegment;
            }

            if (baseObject is Asn1OctetString)
                return (Asn1OctetString)baseObject;

            // Parser assumes implicit constructed encodings are sequences
            if (baseObject is Asn1Sequence)
                return ((Asn1Sequence)baseObject).ToAsn1OctetString();

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(taggedObject),
                "taggedObject");
        }

        internal readonly byte[] contents;

        /**
         * @param string the octets making up the octet string.
         */
        internal Asn1OctetString(byte[] contents)
        {
			if (null == contents)
				throw new ArgumentNullException("contents");

			this.contents = contents;
        }

        public Stream GetOctetStream()
		{
			return new MemoryStream(contents, false);
		}

		public Asn1OctetStringParser Parser
		{
			get { return this; }
		}

		public virtual byte[] GetOctets()
        {
            return contents;
        }

		protected override int Asn1GetHashCode()
		{
			return Arrays.GetHashCode(GetOctets());
        }

		protected override bool Asn1Equals(
			Asn1Object asn1Object)
		{
			DerOctetString other = asn1Object as DerOctetString;

			if (other == null)
				return false;

			return Arrays.AreEqual(GetOctets(), other.GetOctets());
		}

		public override string ToString()
		{
			return "#" + Hex.ToHexString(contents);
		}
	}
}
