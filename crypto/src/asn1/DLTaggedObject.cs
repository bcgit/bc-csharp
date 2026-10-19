using System;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Tagged ASN.1 object with definite-length (DL) encoding.</summary>
    public class DLTaggedObject
        : DerTaggedObject
    {
        /// <summary>Create a new <see cref="DLTaggedObject"/>.</summary>
        /// <param name="tagNo">The tag no.</param>
        /// <param name="obj">The object.</param>
        public DLTaggedObject(int tagNo, Asn1Encodable obj)
            : base(tagNo, obj)
        {
        }

        /// <summary>Create a new <see cref="DLTaggedObject"/>.</summary>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag no.</param>
        /// <param name="obj">The object.</param>
        public DLTaggedObject(int tagClass, int tagNo, Asn1Encodable obj)
            : base(tagClass, tagNo, obj)
        {
        }

        /// <summary>Create a new <see cref="DLTaggedObject"/>.</summary>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <param name="tagNo">The tag no.</param>
        /// <param name="obj">The object.</param>
        public DLTaggedObject(bool isExplicit, int tagNo, Asn1Encodable obj)
            : base(isExplicit, tagNo, obj)
        {
        }

        /// <summary>Create a new <see cref="DLTaggedObject"/>.</summary>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag no.</param>
        /// <param name="obj">The object.</param>
        public DLTaggedObject(bool isExplicit, int tagClass, int tagNo, Asn1Encodable obj)
            : base(isExplicit, tagClass, tagNo, obj)
        {
        }

        internal DLTaggedObject(int explicitness, int tagClass, int tagNo, Asn1Encodable obj)
            : base(explicitness, tagClass, tagNo, obj)
        {
        }

        internal override IAsn1Encoding GetEncoding(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncoding(encoding);

            encoding = Asn1OutputStream.EncodingDL;

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();

            if (!IsExplicit())
                return baseObject.GetEncodingImplicit(encoding, TagClass, TagNo);

            return new TaggedDLEncoding(TagClass, TagNo, baseObject.GetEncoding(encoding));
        }

        internal override IAsn1Encoding GetEncodingImplicit(int encoding, int tagClass, int tagNo)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.GetEncodingImplicit(encoding, tagClass, tagNo);

            encoding = Asn1OutputStream.EncodingDL;

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();

            if (!IsExplicit())
                return baseObject.GetEncodingImplicit(encoding, tagClass, tagNo);

            return new TaggedDLEncoding(tagClass, tagNo, baseObject.GetEncoding(encoding));
        }

        internal override Asn1Sequence RebuildConstructed(Asn1Object asn1Object)
        {
            return new DLSequence(asn1Object);
        }

        internal override Asn1TaggedObject ReplaceTag(int tagClass, int tagNo)
        {
            return new DLTaggedObject(m_explicitness, tagClass, tagNo, m_object);
        }
    }
}
