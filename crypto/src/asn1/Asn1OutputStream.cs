using System;
using System.Diagnostics;
using System.IO;
#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
using System.Buffers.Binary;
using System.Numerics;
#endif

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    public class Asn1OutputStream
        : FilterStream
    {
        internal const int EncodingBer = 1;
        internal const int EncodingDer = 2;

        public static Asn1OutputStream Create(Stream output)
        {
            return Create(output, Asn1Encodable.Ber);
        }

        public static Asn1OutputStream Create(Stream output, string encoding)
        {
            return Create(output, encoding, false);
        }

        public static Asn1OutputStream Create(Stream output, string encoding, bool leaveOpen)
        {
            if (Asn1Encodable.Der.Equals(encoding))
                return new DerOutputStream(output, leaveOpen);

            return new Asn1OutputStream(output, leaveOpen);
        }

        internal static int GetEncodingType(string encoding)
        {
            if (Asn1Encodable.Der.Equals(encoding))
                return EncodingDer;

            return EncodingBer;
        }

        private readonly bool m_leaveOpen;

        protected internal Asn1OutputStream(Stream output, bool leaveOpen)
            : base(output)
        {
            if (!output.CanWrite)
                throw new ArgumentException("Expected stream to be writable", nameof(output));

            m_leaveOpen = leaveOpen;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                FlushInternal();
            }

            if (m_leaveOpen)
            {
                base.Detach(disposing);
            }
            else
            {
                base.Dispose(disposing);
            }
        }

        public virtual void WriteObject(Asn1Encodable asn1Encodable)
        {
            if (null == asn1Encodable)
                throw new ArgumentNullException("asn1Encodable");

            asn1Encodable.ToAsn1Object().GetEncoding(this.Encoding).Encode(this);
            FlushInternal();
        }

        public virtual void WriteObject(Asn1Object asn1Object)
        {
            if (null == asn1Object)
                throw new ArgumentNullException("asn1Object");

            asn1Object.GetEncoding(this.Encoding).Encode(this);
            FlushInternal();
        }

        internal void EncodeContents(IAsn1Encoding[] contentsEncodings)
        {
            for (int i = 0, count = contentsEncodings.Length; i < count; ++i)
            {
                contentsEncodings[i].Encode(this);
            }
        }

        internal virtual int Encoding
        {
            get { return EncodingBer; }
        }

        private void FlushInternal()
        {
            // Placeholder to support future internal buffering
        }

        internal void WriteDL(int dl)
        {
            if (dl < 128)
            {
                Debug.Assert(dl >= 0);
                WriteByte((byte)dl);
                return;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> encoding = stackalloc byte[5];
            BinaryPrimitives.WriteUInt32BigEndian(encoding[1..], (uint)dl);
            int leadingZeroBytes = BitOperations.LeadingZeroCount((uint)dl) / 8;
            encoding[leadingZeroBytes] = (byte)(0x84 - leadingZeroBytes);
            Write(encoding[leadingZeroBytes..]);
#else
            byte[] stack = new byte[5];
            int pos = stack.Length;

            do
            {
                stack[--pos] = (byte)dl;
                dl >>= 8;
            }
            while (dl > 0);

            int count = stack.Length - pos;
            stack[--pos] = (byte)(0x80 | count);

            Write(stack, pos, count + 1);
#endif
        }

        internal void WriteIdentifier(int flags, int tagNo)
        {
            if (tagNo < 31)
            {
                WriteByte((byte)(flags | tagNo));
                return;
            }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Span<byte> stack = stackalloc byte[6];
#else
            byte[] stack = new byte[6];
#endif
            int pos = stack.Length;

            stack[--pos] = (byte)(tagNo & 0x7F);
            while (tagNo > 127)
            {
                tagNo >>= 7;
                stack[--pos] = (byte)(tagNo & 0x7F | 0x80);
            }

            stack[--pos] = (byte)(flags | 0x1F);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
            Write(stack[pos..]);
#else
            Write(stack, pos, stack.Length - pos);
#endif
        }

        internal static IAsn1Encoding[] GetContentsEncodings(int encoding, Asn1Encodable[] elements)
        {
            int count = elements.Length;
            IAsn1Encoding[] contentsEncodings = new IAsn1Encoding[count];
            for (int i = 0; i < count; ++i)
            {
                contentsEncodings[i] = elements[i].ToAsn1Object().GetEncoding(encoding);
            }
            return contentsEncodings;
        }

        internal static DerEncoding[] GetContentsEncodingsDer(Asn1Encodable[] elements)
        {
            int count = elements.Length;
            DerEncoding[] contentsEncodings = new DerEncoding[count];
            for (int i = 0; i < count; ++i)
            {
                contentsEncodings[i] = elements[i].ToAsn1Object().GetEncodingDer();
            }
            return contentsEncodings;
        }

        internal static int GetLengthOfContents(IAsn1Encoding[] contentsEncodings)
        {
            int contentsLength = 0;
            for (int i = 0, count = contentsEncodings.Length; i < count; ++i)
            {
                contentsLength += contentsEncodings[i].GetLength();
            }
            return contentsLength;
        }

        internal static int GetLengthOfDL(int dl)
        {
            if (dl < 128)
                return 1;

            int length = 2;
            while ((dl >>= 8) > 0)
            {
                ++length;
            }
            return length;
        }

        internal static int GetLengthOfEncodingDL(int tagNo, int contentsLength)
        {
            return GetLengthOfIdentifier(tagNo) + GetLengthOfDL(contentsLength) + contentsLength;
        }

        internal static int GetLengthOfEncodingIL(int tagNo, IAsn1Encoding contentsEncoding)
        {
            return GetLengthOfIdentifier(tagNo) + 3 + contentsEncoding.GetLength();
        }

        internal static int GetLengthOfEncodingIL(int tagNo, IAsn1Encoding[] contentsEncodings)
        {
            return GetLengthOfIdentifier(tagNo) + 3 + GetLengthOfContents(contentsEncodings);
        }

        internal static int GetLengthOfIdentifier(int tagNo)
        {
            if (tagNo < 31)
                return 1;

            int length = 2;
            while ((tagNo >>= 7) > 0)
            {
                ++length;
            }
            return length;
        }
    }
}
