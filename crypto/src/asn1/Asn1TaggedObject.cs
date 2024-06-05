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
        private const int DeclaredExplicit = 1;
        private const int DeclaredImplicit = 2;
        // TODO It will probably be better to track parsing constructed vs primitive instead
        private const int ParsedExplicit = 3;
        private const int ParsedImplicit = 4;

        public static Asn1TaggedObject GetInstance(object obj)
		{
            if (obj == null)
                return null;

            if (obj is Asn1TaggedObject asn1TaggedObject)
                return asn1TaggedObject;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                if (!(obj is Asn1Object) && asn1Convertible.ToAsn1Object() is Asn1TaggedObject converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return CheckedCast(FromByteArray(bytes));
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct tagged object from byte[]", nameof(obj), e);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
		}

        public static Asn1TaggedObject GetInstance(object obj, int tagClass)
        {
            return Asn1Utilities.CheckTagClass(CheckInstance(obj), tagClass);
        }

        public static Asn1TaggedObject GetInstance(object obj, int tagClass, int tagNo)
        {
            return Asn1Utilities.CheckTag(CheckInstance(obj), tagClass, tagNo);
        }

        public static Asn1TaggedObject GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return Asn1Utilities.GetExplicitContextBaseTagged(CheckInstance(taggedObject, declaredExplicit));
        }

        public static Asn1TaggedObject GetInstance(Asn1TaggedObject taggedObject, int tagClass, bool declaredExplicit)
        {
            return Asn1Utilities.GetExplicitBaseTagged(CheckInstance(taggedObject, declaredExplicit), tagClass);
        }

        public static Asn1TaggedObject GetInstance(Asn1TaggedObject taggedObject, int tagClass, int tagNo,
            bool declaredExplicit)
        {
            return Asn1Utilities.GetExplicitBaseTagged(CheckInstance(taggedObject, declaredExplicit), tagClass, tagNo);
        }

        public static Asn1TaggedObject GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Asn1TaggedObject existing)
                return existing;

            if (element is IAsn1Convertible asn1Convertible && !(element is Asn1Object) &&
                asn1Convertible.ToAsn1Object() is Asn1TaggedObject converted)
            {
                return converted;
            }

            return null;
        }

        private static Asn1TaggedObject CheckInstance(object obj)
        {
            return GetInstance(obj ?? throw new ArgumentNullException(nameof(obj)));
        }

        private static Asn1TaggedObject CheckInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            if (!declaredExplicit)
                throw new ArgumentException("this method not valid for implicitly tagged tagged objects");

            return taggedObject ?? throw new ArgumentNullException(nameof(taggedObject));
        }

        internal readonly int m_explicitness;
        internal readonly int m_tagClass;
        internal readonly int m_tagNo;
        internal readonly Asn1Encodable m_object;

		/**
         * @param explicitly true if the object is explicitly tagged.
         * @param tagNo the tag number for this object.
         * @param obj the tagged object.
         */
        protected Asn1TaggedObject(bool isExplicit, int tagNo, Asn1Encodable obj)
            : this(isExplicit, Asn1Tags.ContextSpecific, tagNo, obj)
        {
        }

        protected Asn1TaggedObject(bool isExplicit, int tagClass, int tagNo, Asn1Encodable obj)
            : this(isExplicit ? DeclaredExplicit : DeclaredImplicit, tagClass, tagNo, obj)
        {
        }

        internal Asn1TaggedObject(int explicitness, int tagClass, int tagNo, Asn1Encodable obj)
        {
            if (null == obj)
                throw new ArgumentNullException(nameof(obj));
            if (Asn1Tags.Universal == tagClass || (tagClass & Asn1Tags.Private) != tagClass)
                throw new ArgumentException("invalid tag class: " + tagClass, nameof(tagClass));

            m_explicitness = obj is IAsn1Choice ? DeclaredExplicit : explicitness;
            m_tagClass = tagClass;
            m_tagNo = tagNo;
            m_object = obj;
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            Asn1TaggedObject that = asn1Object as Asn1TaggedObject;
            if (null == that || this.m_tagNo != that.m_tagNo || this.m_tagClass != that.m_tagClass)
                return false;

            if (this.m_explicitness != that.m_explicitness)
            {
                /*
                 * TODO This seems incorrect for some cases of implicit tags e.g. if one is a
                 * declared-implicit SET and the other a parsed object.
                 */
                if (this.IsExplicit() != that.IsExplicit())
                    return false;
            }

            Asn1Object p1 = this.m_object.ToAsn1Object();
            Asn1Object p2 = that.m_object.ToAsn1Object();

            if (p1 == p2)
                return true;

            if (!this.IsExplicit())
            {
                try
                {
                    byte[] d1 = this.GetEncoded();
                    byte[] d2 = that.GetEncoded();

                    return Arrays.AreEqual(d1, d2);
                }
                catch (IOException)
                {
                    return false;
                }
            }

            return p1.CallAsn1Equals(p2);
		}

		protected override int Asn1GetHashCode()
		{
            return (m_tagClass * 7919) ^ m_tagNo ^ (IsExplicit() ? 0x0F : 0xF0) ^ m_object.ToAsn1Object().CallAsn1GetHashCode();
        }

        public int TagClass => m_tagClass;

        public int TagNo => m_tagNo;

        public bool HasContextTag()
        {
            return m_tagClass == Asn1Tags.ContextSpecific;
        }

        public bool HasContextTag(int tagNo)
        {
            return m_tagClass == Asn1Tags.ContextSpecific && m_tagNo == tagNo;
        }

        public bool HasTag(int tagClass, int tagNo)
        {
            return m_tagClass == tagClass && m_tagNo == tagNo;
        }

        public bool HasTagClass(int tagClass)
        {
            return m_tagClass == tagClass;
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
            // TODO New methods like 'IsKnownExplicit' etc. to distinguish uncertain cases?
            switch (m_explicitness)
            {
            case DeclaredExplicit:
            case ParsedExplicit:
                return true;
            default:
                return false;
            }
        }

        internal bool IsParsed()
        {
            switch (m_explicitness)
            {
            case ParsedExplicit:
            case ParsedImplicit:
                return true;
            default:
                return false;
            }
        }

        /// <summary>Return whatever was following the tag.</summary>
        /// <remarks>
        /// Tagged objects are generally context dependent. If you're trying to extract a tagged object you should be
        /// going via the appropriate GetInstance method.
        /// </remarks>
        [Obsolete("Will be removed")]
        public Asn1Object GetObject()
        {
            Asn1Utilities.CheckContextTagClass(this);

            return m_object.ToAsn1Object();
        }

        /// <summary>Needed for open types, until we have better type-guided parsing support.</summary>
        /// <remarks>
        /// Use sparingly for other purposes, and prefer <see cref="GetExplicitBaseTagged"/>,
        /// <see cref="GetImplicitBaseTagged(int, int)"/> or <see cref="GetBaseUniversal(bool, int)"/> where possible.
        /// Before using, check for matching tag <see cref="TagClass">class</see> and <see cref="TagNo">number</see>.
        /// </remarks>
        public Asn1Encodable GetBaseObject()
        {
            return m_object;
        }

        /// <summary>Needed for open types, until we have better type-guided parsing support.</summary>
        /// <remarks>
        /// Use sparingly for other purposes, and prefer <see cref="GetExplicitBaseTagged"/> or
        /// <see cref="GetBaseUniversal(bool, int)"/> where possible. Before using, check for matching tag
        /// <see cref="TagClass">class</see> and <see cref="TagNo">number</see>.
        /// </remarks>
        public Asn1Encodable GetExplicitBaseObject()
        {
            if (!IsExplicit())
                throw new InvalidOperationException("object implicit - explicit expected.");

            return m_object;
        }

        public Asn1TaggedObject GetExplicitBaseTagged()
        {
            if (!IsExplicit())
                throw new InvalidOperationException("object implicit - explicit expected.");

            return CheckedCast(m_object.ToAsn1Object());
        }

        public Asn1TaggedObject GetImplicitBaseTagged(int baseTagClass, int baseTagNo)
        {
            if (Asn1Tags.Universal == baseTagClass || (baseTagClass & Asn1Tags.Private) != baseTagClass)
                throw new ArgumentException("invalid base tag class: " + baseTagClass, nameof(baseTagClass));

            switch (m_explicitness)
            {
            case DeclaredExplicit:
                throw new InvalidOperationException("object explicit - implicit expected.");

            case DeclaredImplicit:
            {
                Asn1TaggedObject declared = CheckedCast(m_object.ToAsn1Object());
                return Asn1Utilities.CheckTag(declared, baseTagClass, baseTagNo);
            }

            // Parsed; return a virtual tag (i.e. that couldn't have been present in the encoding)
            default:
                return ReplaceTag(baseTagClass, baseTagNo);
            }
        }

        public Asn1Object GetBaseUniversal(bool declaredExplicit, int tagNo)
        {
            Asn1UniversalType universalType = Asn1UniversalTypes.Get(tagNo)
                ?? throw new ArgumentException("unsupported UNIVERSAL tag number: " + tagNo, nameof(tagNo));

            return GetBaseUniversal(declaredExplicit, universalType);
        }

        internal Asn1Object GetBaseUniversal(bool declaredExplicit, Asn1UniversalType universalType)
        {
            if (declaredExplicit)
            {
                if (!IsExplicit())
                    throw new InvalidOperationException("object explicit - implicit expected.");

                return universalType.CheckedCast(m_object.ToAsn1Object());
            }

            if (DeclaredExplicit == m_explicitness)
                throw new InvalidOperationException("object explicit - implicit expected.");

            Asn1Object baseObject = m_object.ToAsn1Object();
            switch (m_explicitness)
            {
            case ParsedExplicit:
                return universalType.FromImplicitConstructed(RebuildConstructed(baseObject));
            case ParsedImplicit:
            {
                if (baseObject is Asn1Sequence asn1Sequence)
                    return universalType.FromImplicitConstructed(asn1Sequence);

                return universalType.FromImplicitPrimitive((DerOctetString)baseObject);
            }
            default:
                return universalType.CheckedCast(baseObject);
            }
        }

        public IAsn1Convertible ParseBaseUniversal(bool declaredExplicit, int baseTagNo)
        {
            Asn1Object asn1Object = GetBaseUniversal(declaredExplicit, baseTagNo);

            switch (baseTagNo)
            {
            case Asn1Tags.BitString:
                return ((DerBitString)asn1Object).Parser;
            case Asn1Tags.OctetString:
                return ((Asn1OctetString)asn1Object).Parser;
            case Asn1Tags.Sequence:
                return ((Asn1Sequence)asn1Object).Parser;
            case Asn1Tags.Set:
                return ((Asn1Set)asn1Object).Parser;
            }

            return asn1Object;
        }

        public IAsn1Convertible ParseExplicitBaseObject()
        {
            return GetExplicitBaseObject();
        }

        public Asn1TaggedObjectParser ParseExplicitBaseTagged()
        {
            return GetExplicitBaseTagged();
        }

        public Asn1TaggedObjectParser ParseImplicitBaseTagged(int baseTagClass, int baseTagNo)
        {
            return GetImplicitBaseTagged(baseTagClass, baseTagNo);
        }

		public override string ToString()
		{
            return Asn1Utilities.GetTagText(m_tagClass, m_tagNo) + m_object;
		}

        internal abstract Asn1Sequence RebuildConstructed(Asn1Object asn1Object);

        internal abstract Asn1TaggedObject ReplaceTag(int tagClass, int tagNo);

        internal static Asn1Object CreateConstructedDL(int tagClass, int tagNo, Asn1EncodableVector contentsElements)
        {
            bool maybeExplicit = (contentsElements.Count == 1);

            return maybeExplicit
                ? new DLTaggedObject(ParsedExplicit, tagClass, tagNo, contentsElements[0])
                : new DLTaggedObject(ParsedImplicit, tagClass, tagNo, DLSequence.FromVector(contentsElements));
        }

        internal static Asn1Object CreateConstructedIL(int tagClass, int tagNo, Asn1EncodableVector contentsElements)
        {
            bool maybeExplicit = (contentsElements.Count == 1);

            return maybeExplicit
                ? new BerTaggedObject(ParsedExplicit, tagClass, tagNo, contentsElements[0])
                : new BerTaggedObject(ParsedImplicit, tagClass, tagNo, BerSequence.FromVector(contentsElements));
        }

        internal static Asn1Object CreatePrimitive(int tagClass, int tagNo, byte[] contentsOctets)
        {
            // Note: !CONSTRUCTED => IMPLICIT
            return new DLTaggedObject(ParsedImplicit, tagClass, tagNo, new DerOctetString(contentsOctets));
        }

        private static Asn1TaggedObject CheckedCast(Asn1Object asn1Object)
        {
            Asn1TaggedObject taggedObject = asn1Object as Asn1TaggedObject;
            if (null != taggedObject)
                return taggedObject;

            throw new InvalidOperationException("unexpected object: " + Platform.GetTypeName(asn1Object));
        }
    }
}
