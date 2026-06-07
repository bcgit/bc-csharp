using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public abstract class DerGenerator
        : Asn1Generator
    {
        private bool _tagged = false;
        private bool _isExplicit;
        private int _tagNo;

        protected DerGenerator(Stream outStream)
            : base(outStream)
        {
        }

        protected DerGenerator(Stream outStream, int tagNo, bool isExplicit)
            : base(outStream)
        {
            _tagged = true;
            _isExplicit = isExplicit;
            _tagNo = tagNo;
        }

        internal void WriteDerEncoded(int tag, byte[] bytes)
        {
            if (!_tagged)
            {
                WriteDerEncoded(OutStream, tag, bytes);
            }
            else if (_isExplicit)
            {
                /*
                 * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
                 * and the contents octets shall be the complete base encoding.
                 */
                MemoryStream buf = new MemoryStream();
                WriteDerEncoded(buf, tag, bytes);
                WriteDerEncoded(OutStream, Asn1Tags.ContextSpecific | Asn1Tags.Constructed, _tagNo, buf.ToArray());
            }
            else
            {
                /*
                 * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
                 * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
                 * shall be [..] the contents octets of the base encoding.
                 */
                WriteDerEncoded(OutStream, InheritConstructedFlag(Asn1Tags.ContextSpecific, tag), _tagNo, bytes);
            }
        }

        internal static void WriteDerEncoded(Stream outStream, int tag, byte[] bytes)
        {
            outStream.WriteByte((byte)tag);
            Asn1OutputStream.WriteDL(outStream, bytes.Length);
            outStream.Write(bytes, 0, bytes.Length);
        }

        private void WriteDerEncoded(Stream outStream, int flags, int tagNo, byte[] bytes)
        {
            Asn1OutputStream.WriteIdentifier(outStream, flags, tagNo);
            Asn1OutputStream.WriteDL(outStream, bytes.Length);
            outStream.Write(bytes, 0, bytes.Length);
        }
    }
}
