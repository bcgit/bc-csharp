using System;
using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1
{
    /**
     * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
     * a [n] where n is some number - these are assumed to follow the construction
     * rules (as with sequences).
     */
    public abstract class Asn1TaggedObject
		: Asn1Object, Asn1TaggedObjectParser
    {
        // TODO[asn1] Rewrite DerApplicationSpecific in terms of Asn1TaggedObject and remove this
        internal static bool IsConstructed(bool isExplicit, Asn1Object obj)
        {
            if (isExplicit || obj is Asn1Sequence || obj is Asn1Set)
                return true;
            Asn1TaggedObject tagged = obj as Asn1TaggedObject;
            if (tagged == null)
                return false;
            return IsConstructed(tagged.IsExplicit(), tagged.GetObject());
        }

		public static Asn1TaggedObject GetInstance(object obj)
		{
            if (obj == null || obj is Asn1TaggedObject) 
            {
                return (Asn1TaggedObject)obj;
            }
            //else if (obj is Asn1TaggedObjectParser)
            else if (obj is IAsn1Convertible)
            {
                Asn1Object asn1Object = ((IAsn1Convertible)obj).ToAsn1Object();
                if (asn1Object is Asn1TaggedObject)
                    return (Asn1TaggedObject)asn1Object;
            }
            else if (obj is byte[])
            {
                try
                {
                    return CheckedCast(FromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct tagged object from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
		}

        public static Asn1TaggedObject GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            if (Asn1Tags.ContextSpecific != taggedObject.TagClass)
                throw new InvalidOperationException("this method only valid for CONTEXT_SPECIFIC tags");

            if (!declaredExplicit)
                throw new ArgumentException("this method not valid for implicitly tagged tagged objects");

            return taggedObject.GetExplicitBaseTagged();
        }

        internal readonly int tagClass = Asn1Tags.ContextSpecific;
        internal readonly int tagNo;
        internal readonly bool explicitly;
        internal readonly Asn1Encodable obj;

        /**
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        protected Asn1TaggedObject(int tagNo, Asn1Encodable obj)
            : this(true, tagNo, obj)
        {
        }

		/**
         * @param explicitly true if the object is explicitly tagged.
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        protected Asn1TaggedObject(bool explicitly, int tagNo, Asn1Encodable obj)
        {
            if (null == obj)
                throw new ArgumentNullException("obj");

            // IAsn1Choice marker interface 'insists' on explicit tagging
            this.explicitly = explicitly || (obj is IAsn1Choice);
            this.tagNo = tagNo;
            this.obj = obj;
        }

		protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            if (asn1Object is DerApplicationSpecific)
                return asn1Object.CallAsn1Equals(this);

            Asn1TaggedObject that = asn1Object as Asn1TaggedObject;
            return null != that
                && this.tagClass == that.tagClass
                && this.tagNo == that.tagNo
                && this.explicitly == that.explicitly   // TODO Should this be part of equality?
                && this.GetObject().Equals(that.GetObject());
		}

		protected override int Asn1GetHashCode()
		{
            int code = (tagClass * 7919) ^ tagNo;

			// TODO: actually this is wrong - the problem is that a re-encoded
			// object may end up with a different hashCode due to implicit
			// tagging. As implicit tagging is ambiguous if a sequence is involved
			// it seems the only correct method for both equals and hashCode is to
			// compare the encodings...
//			code ^= explicitly.GetHashCode();

            code ^= obj.GetHashCode();

			return code;
        }

        public int TagClass
        {
            get { return tagClass; }
        }

		public int TagNo
        {
			get { return tagNo; }
        }

        public bool HasContextTag(int tagNo)
        {
            return this.tagClass == Asn1Tags.ContextSpecific && this.tagNo == tagNo;
        }

        public bool HasTag(int tagClass, int tagNo)
        {
            return this.tagClass == tagClass && this.tagNo == tagNo;
        }

        /**
         * return whether or not the object may be explicitly tagged.
         * <p>
         * Note: if the object has been read from an input stream, the only
         * time you can be sure if isExplicit is returning the true state of
         * affairs is if it returns false. An implicitly tagged object may appear
         * to be explicitly tagged, so you need to understand the context under
         * which the reading was done as well, see GetObject below.</p>
         */
        public bool IsExplicit()
        {
            return explicitly;
        }

        [Obsolete("Will be removed. Replace with constant return value of 'false'")]
        public bool IsEmpty()
        {
            return false;
        }

        /**
         * Return the contents of this object as a byte[]
         *
         * @return the encoded contents of the object.
         */
        // TODO Need this public if/when DerApplicationSpecific extends Asn1TaggedObject
        internal byte[] GetContents()
        {
            try
            {
                byte[] baseEncoding = obj.GetEncoded(Asn1Encoding);
                if (IsExplicit())
                    return baseEncoding;

                MemoryStream input = new MemoryStream(baseEncoding, false);
                int tag = input.ReadByte();
                Asn1InputStream.ReadTagNumber(input, tag);
                int length = Asn1InputStream.ReadLength(input, (int)(input.Length - input.Position), false);
                int remaining = (int)(input.Length - input.Position);

                // For indefinite form, account for end-of-contents octets
                int contentsLength = length < 0 ? remaining - 2 : remaining;
                if (contentsLength < 0)
                    throw new InvalidOperationException("failed to get contents");

                byte[] contents = new byte[contentsLength];
                Array.Copy(baseEncoding, baseEncoding.Length - remaining, contents, 0, contentsLength);
                return contents;
            }
            catch (IOException e)
            {
                throw new InvalidOperationException("failed to get contents", e);
            }
        }

        /**
         * Return true if the object is marked as constructed, false otherwise.
         *
         * @return true if constructed, otherwise false.
         */
        // TODO Need this public if/when DerApplicationSpecific extends Asn1TaggedObject
        internal bool IsConstructed()
        {
            return EncodeConstructed();
        }

        /**
         * return whatever was following the tag.
         * <p>
         * Note: tagged objects are generally context dependent if you're
         * trying to extract a tagged object you should be going via the
         * appropriate GetInstance method.</p>
         */
        public Asn1Object GetObject()
        {
            if (Asn1Tags.ContextSpecific != TagClass)
                throw new InvalidOperationException("this method only valid for CONTEXT_SPECIFIC tags");

            return obj.ToAsn1Object();
        }

        /**
         * Needed for open types, until we have better type-guided parsing support. Use sparingly for other
         * purposes, and prefer {@link #getExplicitBaseTagged()}, {@link #getImplicitBaseTagged(int, int)} or
         * {@link #getBaseUniversal(boolean, int)} where possible. Before using, check for matching tag
         * {@link #getTagClass() class} and {@link #getTagNo() number}.
         */
        public Asn1Encodable GetBaseObject()
        {
            return obj;
        }

        /**
         * Needed for open types, until we have better type-guided parsing support. Use
         * sparingly for other purposes, and prefer {@link #getExplicitBaseTagged()} or
         * {@link #getBaseUniversal(boolean, int)} where possible. Before using, check
         * for matching tag {@link #getTagClass() class} and {@link #getTagNo() number}.
         */
        public Asn1Encodable GetExplicitBaseObject()
        {
            if (!IsExplicit())
                throw new InvalidOperationException("object implicit - explicit expected.");

            return obj;
        }

        public Asn1TaggedObject GetExplicitBaseTagged()
        {
            if (!IsExplicit())
                throw new InvalidOperationException("object implicit - explicit expected.");

            return CheckedCast(obj.ToAsn1Object());
        }

        /**
		* Return the object held in this tagged object as a parser assuming it has
		* the type of the passed in tag. If the object doesn't have a parser
		* associated with it, the base object is returned.
		*/
        public IAsn1Convertible GetObjectParser(int tag, bool isExplicit)
		{
            if (Asn1Tags.ContextSpecific != TagClass)
                throw new InvalidOperationException("this method only valid for CONTEXT_SPECIFIC tags");

            switch (tag)
			{
            //case Asn1Tags.BitString:
            //    return Asn1BitString.GetInstance(this, isExplicit).Parser;
            case Asn1Tags.OctetString:
                return Asn1OctetString.GetInstance(this, isExplicit).Parser;
            case Asn1Tags.Sequence:
                return Asn1Sequence.GetInstance(this, isExplicit).Parser;
            case Asn1Tags.Set:
				return Asn1Set.GetInstance(this, isExplicit).Parser;
			}

			if (isExplicit)
			{
				return GetObject();
			}

			throw Platform.CreateNotImplementedException("implicit tagging for tag: " + tag);
		}

		public override string ToString()
		{
            return Asn1Utilities.GetTagText(tagClass, tagNo) + obj;
		}

        internal abstract string Asn1Encoding { get; }

        internal abstract Asn1Sequence RebuildConstructed(Asn1Object asn1Object);

        private static Asn1TaggedObject CheckedCast(Asn1Object asn1Object)
        {
            Asn1TaggedObject taggedObject = asn1Object as Asn1TaggedObject;
            if (null != taggedObject)
                return taggedObject;

            throw new InvalidOperationException("unexpected object: " + Platform.GetTypeName(asn1Object));
        }
    }
}
