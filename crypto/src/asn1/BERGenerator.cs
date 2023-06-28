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
            if (_tagged)
            {
                int tagNum = _tagNo | Asn1Tags.ContextSpecific;

                if (_isExplicit)
                {
                    WriteHdr(tagNum | Asn1Tags.Constructed);
                    WriteHdr(tag);
                }
                else
                {
                    if ((tag & Asn1Tags.Constructed) != 0)
                    {
                        WriteHdr(tagNum | Asn1Tags.Constructed);
                    }
                    else
                    {
                        WriteHdr(tagNum);
                    }
                }
            }
            else
            {
                WriteHdr(tag);
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
