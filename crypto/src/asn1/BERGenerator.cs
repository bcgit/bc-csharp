using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Base class for the generators that write BER encoded objects to a stream piece by piece.</summary>
    public abstract class BerGenerator
        : Asn1Generator
    {
        private bool _tagged = false;
        private bool _isExplicit;
        private int _tagNo;

        /// <summary>Create a new <see cref="BerGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        protected BerGenerator(Stream outStream)
            : base(outStream)
        {
        }

        /// <summary>Create a new <see cref="BerGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        /// <param name="tagNo">The tag no.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        protected BerGenerator(Stream outStream, int tagNo, bool isExplicit)
            : base(outStream)
        {
            _tagged = true;
            _isExplicit = isExplicit;
            _tagNo = tagNo;
        }

        /// <inheritdoc/>
        protected override void Finish()
        {
            WriteBerEnd();
        }

        /// <inheritdoc/>
        public override void AddObject(Asn1Encodable obj)
        {
            obj.EncodeTo(OutStream);
        }

        /// <inheritdoc/>
        public override void AddObject(Asn1Object obj)
        {
            obj.EncodeTo(OutStream);
        }

        /// <inheritdoc/>
        public override Stream GetRawOutputStream()
        {
            return OutStream;
        }

        private void WriteHdr(int tag)
        {
            OutStream.WriteByte((byte)tag);
            OutStream.WriteByte(0x80);
        }

        private void WriteHdr(int flags, int tagNo)
        {
            Asn1OutputStream.WriteIdentifier(OutStream, flags, tagNo);
            OutStream.WriteByte(0x80);
        }

        /// <summary>Write the header of a BER constructed object with indefinite length.</summary>
        /// <param name="tag">The tag of the object.</param>
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
                WriteHdr(Asn1Tags.ContextSpecific | Asn1Tags.Constructed, _tagNo);
                WriteHdr(tag);
            }
            else
            {
                /*
                 * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
                 * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
                 * shall be [..] the contents octets of the base encoding.
                 */
                WriteHdr(InheritConstructedFlag(Asn1Tags.ContextSpecific, tag), _tagNo);
            }
        }

        /// <summary>Copy the body of a BER constructed object to the output.</summary>
        /// <param name="contentStream">The stream holding the body.</param>
        // TODO[api] Remove unnecessary method
        protected void WriteBerBody(Stream contentStream)
        {
            Streams.PipeAll(contentStream, OutStream);
        }

        /// <summary>Write the end-of-contents octets of a BER constructed object with indefinite length.</summary>
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
