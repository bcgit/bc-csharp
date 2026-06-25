using System;
using System.IO;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    public class Pkcs7ProcessableObject
        : CmsTypedData
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly Asn1Encodable m_content;

        public Pkcs7ProcessableObject(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            m_contentType = contentType;
            m_content = content;
        }

        public Asn1Encodable Content => m_content;

        public DerObjectIdentifier ContentType => m_contentType;

        public void Write(Stream outStream)
        {
            Asn1Sequence seq = Asn1Sequence.GetOptional(m_content);
            if (seq != null)
            {
                foreach (var element in seq)
                {
                    element.EncodeTo(outStream, Asn1Encodable.Der);
                }
            }
            else
            {
                byte[] encoded = m_content.GetEncoded(Asn1Encodable.Der);

                int index = 1;
                while ((encoded[index] & 0x80) != 0)
                {
                    index++;
                }
                index++;

                outStream.Write(encoded, index, encoded.Length - index);
            }
        }

        [Obsolete("Use 'Content' property instead")]
        public object GetContent() => m_content;
    }
}
