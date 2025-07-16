using System.IO;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Cms
{
    public class Pkcs7ProcessableObject
        : CmsProcessable
    {
        public DerObjectIdentifier ContentType { get; }
        public Asn1Encodable Content { get; }

        public Pkcs7ProcessableObject(DerObjectIdentifier contentType, Asn1Encodable content)
        {
            ContentType = contentType;
            Content = content;
        }

        public void Write(Stream outStream)
        {
            Asn1Sequence seq = Asn1Sequence.GetOptional(Content);
            if (seq != null)
            {
                foreach (var element in seq)
                {
                    element.EncodeTo(outStream, Asn1Encodable.Der);
                }
            }
            else
            {
                byte[] encoded = Content.GetEncoded(Asn1Encodable.Der);
                int index = 1;
                while ((encoded[index] & 0x80) != 0)
                {
                    index++;
                }

                index++;
                outStream.Write(encoded, index, encoded.Length - index);
            }
        }

        public object GetContent() => Content;
    }
}
