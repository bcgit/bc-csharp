using System;
using System.IO;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    /// <summary>Typed CMS content backed by an ASN.1 object, written as the DER encoding of its contents.</summary>
    public class Pkcs7ProcessableObject
        : CmsTypedData
    {
        private readonly DerObjectIdentifier m_contentType;
        private readonly Asn1Encodable m_content;

        /// <summary>Create a new <see cref="Pkcs7ProcessableObject"/>.</summary>
        /// <param name="contentType">The content type.</param>
        /// <param name="content">The content.</param>
        public Pkcs7ProcessableObject(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            m_contentType = contentType;
            m_content = content;
        }

        /// <summary>Gets the content.</summary>
        public Asn1Encodable Content => m_content;

        /// <inheritdoc/>
        public DerObjectIdentifier ContentType => m_contentType;

        /// <summary>
        /// Write the content to a stream. If the content is a sequence, its elements are written one after another in
        /// DER encoding; otherwise the contents octets of its DER encoding are written (without tag and length).
        /// </summary>
        /// <param name="outStream">The stream to write to.</param>
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

        /// <summary>Return the content.</summary>
        [Obsolete("Use 'Content' property instead")]
        public object GetContent() => m_content;
    }
}
