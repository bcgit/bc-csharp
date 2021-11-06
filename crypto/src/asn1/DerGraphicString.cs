using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    public class DerGraphicString
        : DerStringBase
    {
        /**
         * return a Graphic String from the passed in object
         *
         * @param obj a DerGraphicString or an object that can be converted into one.
         * @exception IllegalArgumentException if the object cannot be converted.
         * @return a DerGraphicString instance, or null.
         */
        public static DerGraphicString GetInstance(object obj)
        {
            if (obj == null || obj is DerGraphicString)
            {
                return (DerGraphicString)obj;
            }

            if (obj is byte[])
            {
                try
                {
                    return (DerGraphicString)FromByteArray((byte[])obj);
                }
                catch (Exception e)
                {
                    throw new ArgumentException("encoding error in GetInstance: " + e.ToString(), "obj");
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        /**
         * return a Graphic String from a tagged object.
         *
         * @param obj the tagged object holding the object we want
         * @param explicit true if the object is meant to be explicitly
         *              tagged false otherwise.
         * @exception IllegalArgumentException if the tagged object cannot
         *               be converted.
         * @return a DerGraphicString instance, or null.
         */
        public static DerGraphicString GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
			Asn1Object o = obj.GetObject();

            if (isExplicit || o is DerGraphicString)
			{
				return GetInstance(o);
			}

            return new DerGraphicString(((Asn1OctetString)o).GetOctets());
        }

        private readonly byte[] m_contents;

        public DerGraphicString(byte[] contents)
            : this(contents, true)
        {
        }

        internal DerGraphicString(byte[] contents, bool clone)
        {
            if (null == contents)
                throw new ArgumentNullException("contents");

            this.m_contents = clone ? Arrays.Clone(contents) : contents;
        }

        public override string GetString()
        {
            return Strings.FromByteArray(m_contents);
        }

        public byte[] GetOctets()
        {
            return Arrays.Clone(m_contents);
        }

        internal override int EncodedLength(bool withID)
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(withID, m_contents.Length);
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            asn1Out.WriteEncodingDL(withID, Asn1Tags.GraphicString, m_contents);
        }

        protected override int Asn1GetHashCode()
		{
            return Arrays.GetHashCode(m_contents);
        }

		protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            DerGraphicString that = asn1Object as DerGraphicString;
            return null != that
                && Arrays.AreEqual(this.m_contents, that.m_contents);
        }

        internal static DerGraphicString CreatePrimitive(byte[] contents)
        {
            return new DerGraphicString(contents, false);
        }
    }
}
