using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1
{
    internal class ConstructedDerEncoding
        : DerEncoding
    {
        private readonly DerEncoding[] m_contentsElements;
        private readonly int m_contentsLength;

        internal ConstructedDerEncoding(int tagClass, int tagNo, DerEncoding[] contentsElements)
            : base(tagClass, tagNo)
        {
            Debug.Assert(contentsElements != null);
            m_contentsElements = contentsElements;
            m_contentsLength = Asn1OutputStream.GetLengthOfContents(contentsElements);
        }

        protected internal override int CompareLengthAndContents(DerEncoding other)
        {
            if (!(other is ConstructedDerEncoding that))
                throw new InvalidOperationException();

            if (this.m_contentsLength != that.m_contentsLength)
                return this.m_contentsLength - that.m_contentsLength;

            int length = System.Math.Min(this.m_contentsElements.Length, that.m_contentsElements.Length);
            for (int i = 0; i < length; i++)
            {
                int c = this.m_contentsElements[i].CompareTo(that.m_contentsElements[i]);
                if (c != 0)
                    return c;
            }

            Debug.Assert(this.m_contentsElements.Length == that.m_contentsElements.Length);
            return this.m_contentsElements.Length - that.m_contentsElements.Length;
        }

        public override void Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteIdentifier(Asn1Tags.Constructed | m_tagClass, m_tagNo);
            asn1Out.WriteDL(m_contentsLength);
            asn1Out.EncodeContents(m_contentsElements);
        }

        public override int GetLength()
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(m_tagNo, m_contentsLength);
        }
    }
}
