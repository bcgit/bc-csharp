using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1
{
    internal class TaggedDerEncoding
        : DerEncoding
    {
        private readonly DerEncoding m_contentsElement;
        private readonly int m_contentsLength;

        internal TaggedDerEncoding(int tagClass, int tagNo, DerEncoding contentsElement)
            : base(tagClass, tagNo)
        {
            Debug.Assert(contentsElement != null);
            m_contentsElement = contentsElement;
            m_contentsLength = contentsElement.GetLength();
        }

        protected internal override int CompareLengthAndContents(DerEncoding other)
        {
            if (!(other is TaggedDerEncoding that))
                throw new InvalidOperationException();

            if (this.m_contentsLength != that.m_contentsLength)
                return this.m_contentsLength - that.m_contentsLength;

            return this.m_contentsElement.CompareTo(that.m_contentsElement);
        }

        public override void Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteIdentifier(Asn1Tags.Constructed | m_tagClass, m_tagNo);
            asn1Out.WriteDL(m_contentsLength);
            m_contentsElement.Encode(asn1Out);
        }

        public override int GetLength()
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(m_tagNo, m_contentsLength);
        }
    }
}
