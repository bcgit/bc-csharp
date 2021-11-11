using System;

namespace Org.BouncyCastle.Asn1
{
    internal class DLTaggedObject
        : DerTaggedObject
    {
        private int m_contentsLengthDL = -1;

        internal DLTaggedObject(int tagNo, Asn1Encodable obj)
            : base(tagNo, obj)
        {
        }

        internal DLTaggedObject(int tagClass, int tagNo, Asn1Encodable obj)
            : base(tagClass, tagNo, obj)
        {
        }

        internal DLTaggedObject(bool isExplicit, int tagNo, Asn1Encodable obj)
            : base(isExplicit, tagNo, obj)
        {
        }

        internal DLTaggedObject(bool isExplicit, int tagClass, int tagNo, Asn1Encodable obj)
            : base(isExplicit, tagClass, tagNo, obj)
        {
        }

        internal DLTaggedObject(int explicitness, int tagClass, int tagNo, Asn1Encodable obj)
            : base(explicitness, tagClass, tagNo, obj)
        {
        }

        internal override string Asn1Encoding
        {
            // TODO[asn1] Use DL encoding when supported
            get { return Ber; }
        }

        internal override bool EncodeConstructed(int encoding)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.EncodeConstructed(encoding);

            // TODO[asn1] Use DL encoding when supported
            //encoding = Asn1OutputStream.EncodingDL;

            return IsExplicit() || GetBaseObject().ToAsn1Object().EncodeConstructed(encoding);
        }

        internal override int EncodedLength(int encoding, bool withID)
        {
            if (Asn1OutputStream.EncodingDer == encoding)
                return base.EncodedLength(encoding, withID);

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();
            bool withBaseID = IsExplicit();

            int length = GetContentsLengthDL(baseObject, withBaseID);

            if (withBaseID)
            {
                length += Asn1OutputStream.GetLengthOfDL(length);
            }

            length += withID ? Asn1OutputStream.GetLengthOfIdentifier(TagNo) : 0;

            return length;
        }

        internal override void Encode(Asn1OutputStream asn1Out, bool withID)
        {
            if (Asn1OutputStream.EncodingDer == asn1Out.Encoding)
            {
                base.Encode(asn1Out, withID);
                return;
            }

            // TODO[asn1] Use DL encoding when supported
            //asn1Out = asn1Out.GetDLSubStream();

            Asn1Object baseObject = GetBaseObject().ToAsn1Object();
            bool withBaseID = IsExplicit();

            if (withID)
            {
                int flags = TagClass;
                if (withBaseID || baseObject.EncodeConstructed(asn1Out.Encoding))
                {
                    flags |= Asn1Tags.Constructed;
                }

                asn1Out.WriteIdentifier(true, flags, TagNo);
            }

            if (withBaseID)
            {
                asn1Out.WriteDL(GetContentsLengthDL(baseObject, true));
            }

            baseObject.Encode(asn1Out, withBaseID);
        }

        internal override Asn1Sequence RebuildConstructed(Asn1Object asn1Object)
        {
            return new DLSequence(asn1Object);
        }

        internal override Asn1TaggedObject ReplaceTag(int tagClass, int tagNo)
        {
            return new DLTaggedObject(explicitness, tagClass, tagNo, obj);
        }

        private int GetContentsLengthDL(Asn1Object baseObject, bool withBaseID)
        {
            if (m_contentsLengthDL < 0)
            {
                // TODO[asn1] Use DL encoding when supported
                m_contentsLengthDL = baseObject.EncodedLength(Asn1OutputStream.EncodingBer, withBaseID);
            }
            return m_contentsLengthDL;
        }
    }
}
