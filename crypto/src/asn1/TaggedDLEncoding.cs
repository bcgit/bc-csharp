using System;

namespace Org.BouncyCastle.Asn1
{
    internal class TaggedDLEncoding
        : IAsn1Encoding
    {
        private readonly int m_tagClass;
        private readonly int m_tagNo;
        private readonly IAsn1Encoding m_contentsElement;
        private readonly int m_contentsLength;

        internal TaggedDLEncoding(int tagClass, int tagNo, IAsn1Encoding contentsElement)
        {
            m_tagClass = tagClass;
            m_tagNo = tagNo;
            m_contentsElement = contentsElement;
            m_contentsLength = contentsElement.GetLength();
        }

        void IAsn1Encoding.Encode(Asn1OutputStream asn1Out)
        {
            asn1Out.WriteIdentifier(Asn1Tags.Constructed | m_tagClass, m_tagNo);
            asn1Out.WriteDL(m_contentsLength);
            m_contentsElement.Encode(asn1Out);
        }

        int IAsn1Encoding.GetLength()
        {
            return Asn1OutputStream.GetLengthOfEncodingDL(m_tagNo, m_contentsLength);
        }
    }
}
