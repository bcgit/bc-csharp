using System.IO;

using Org.BouncyCastle.Utilities.IO;

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
                WriteDerEncoded(OutStream, _tagNo | Asn1Tags.ContextSpecific | Asn1Tags.Constructed, buf.ToArray());
            }
            else
            {
                /*
                 * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
                 * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
                 * shall be [..] the contents octets of the base encoding.
                 */
                WriteDerEncoded(OutStream, InheritConstructedFlag(_tagNo | Asn1Tags.ContextSpecific, tag), bytes);
            }
        }

        internal static void WriteDerEncoded(Stream outStream, int tag, byte[] bytes)
        {
            outStream.WriteByte((byte)tag);
            WriteLength(outStream, bytes.Length);
            outStream.Write(bytes, 0, bytes.Length);
        }

        internal static void WriteDerEncoded(Stream outStream, int tag, Stream inStream)
        {
            WriteDerEncoded(outStream, tag, Streams.ReadAll(inStream));
        }

        private static void WriteLength(Stream outStream, int length)
        {
            if (length > 127)
            {
                int size = 1;
                int val = length;

                while ((val >>= 8) != 0)
                {
                    size++;
                }

                outStream.WriteByte((byte)(size | 0x80));

                for (int i = (size - 1) * 8; i >= 0; i -= 8)
                {
                    outStream.WriteByte((byte)(length >> i));
                }
            }
            else
            {
                outStream.WriteByte((byte)length);
            }
        }
    }
}
