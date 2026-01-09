using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    public abstract class BerGenerator
        : Asn1Generator
    {
        private bool _tagged = false;
        private bool _isExplicit;
        private int _tagNo;

        protected BerGenerator(Stream outStream)
            : base(outStream)
        {
        }

        protected BerGenerator(Stream outStream, int tagNo, bool isExplicit)
            : base(outStream)
        {
            _tagged = true;
            _isExplicit = isExplicit;
            _tagNo = tagNo;
        }

        protected override void Finish()
        {
            WriteBerEnd();
        }

        public override void AddObject(Asn1Encodable obj)
		{
            obj.EncodeTo(OutStream);
		}

        public override void AddObject(Asn1Object obj)
        {
            obj.EncodeTo(OutStream);
        }

        public override Stream GetRawOutputStream()
        {
            return OutStream;
        }

        private void WriteHdr(int tag)
        {
            OutStream.WriteByte((byte)tag);
            OutStream.WriteByte(0x80);
        }

        protected void WriteBerHeader(int tag)
        {
            if (!_tagged)
            {
                WriteHdr(tag);
            }
            else if (_isExplicit)
            {
                /*
                 * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
                 * and the contents octets shall be the complete base encoding.
                 */
                WriteHdr(_tagNo | Asn1Tags.ContextSpecific | Asn1Tags.Constructed);
                WriteHdr(tag);
            }
            else
            {
                /*
                 * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
                 * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
                 * shall be [..] the contents octets of the base encoding.
                 */
                WriteHdr(InheritConstructedFlag(_tagNo | Asn1Tags.ContextSpecific, tag));
            }
        }

		protected void WriteBerBody(Stream contentStream)
        {
			Streams.PipeAll(contentStream, OutStream);
        }

		protected void WriteBerEnd()
        {
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> data = stackalloc byte[4]{ 0x00, 0x00, 0x00, 0x00 };
            if (_tagged && _isExplicit)  // write extra end for tag header
            {
                OutStream.Write(data[..4]);
            }
            else
            {
                OutStream.Write(data[..2]);
            }
#else
            OutStream.WriteByte(0x00);
            OutStream.WriteByte(0x00);

            if (_tagged && _isExplicit)  // write extra end for tag header
            {
                OutStream.WriteByte(0x00);
                OutStream.WriteByte(0x00);
            }
#endif
        }
    }
}
