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
            if (_tagged)
            {
                int tagNum = _tagNo | Asn1Tags.ContextSpecific;

                if (_isExplicit)
                {
                    int newTag = _tagNo | Asn1Tags.Constructed | Asn1Tags.ContextSpecific;
					MemoryStream bOut = new MemoryStream();
                    WriteDerEncoded(bOut, tag, bytes);
                    WriteDerEncoded(OutStream, newTag, bOut.ToArray());
                }
                else
                {
					if ((tag & Asn1Tags.Constructed) != 0)
					{
						tagNum |= Asn1Tags.Constructed;
					}

					WriteDerEncoded(OutStream, tagNum, bytes);
                }
            }
            else
            {
                WriteDerEncoded(OutStream, tag, bytes);
            }
        }

        internal static void WriteDerEncoded(Stream outStream, int tag, byte[] bytes)
        {
            outStream.WriteByte((byte)tag);
            WriteLength(outStream, bytes.Length);
            outStream.Write(bytes, 0, bytes.Length);
        }

        internal static void WriteDerEncoded(Stream	outStream, int tag, Stream	inStream)
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
