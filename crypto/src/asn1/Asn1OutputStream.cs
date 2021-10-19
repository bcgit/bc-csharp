using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public class Asn1OutputStream
        : DerOutputStream
    {
        public static Asn1OutputStream Create(Stream output)
        {
            return new Asn1OutputStream(output);
        }

        public static Asn1OutputStream Create(Stream output, string encoding)
        {
            if (Asn1Encodable.Der.Equals(encoding))
            {
                return new DerOutputStreamNew(output);
            }
            else
            {
                return new Asn1OutputStream(output);
            }
        }

        [Obsolete("Use static Create method(s)")]
        public Asn1OutputStream(Stream os)
            : base(os)
        {
        }

        public override void WriteObject(Asn1Encodable encodable)
        {
            if (null == encodable)
                throw new IOException("null object detected");

            WritePrimitive(encodable.ToAsn1Object(), true);
            FlushInternal();
        }

        public override void WriteObject(Asn1Object primitive)
        {
            if (null == primitive)
                throw new IOException("null object detected");

            WritePrimitive(primitive, true);
            FlushInternal();
        }

        internal void FlushInternal()
        {
            // Placeholder to support future internal buffering
        }

        internal virtual bool IsBer
        {
            get { return true; }
        }

        internal void WriteDL(int length)
        {
            if (length < 128)
            {
                WriteByte((byte)length);
            }
            else
            {
                byte[] stack = new byte[5];
                int pos = stack.Length;

                do
                {
                    stack[--pos] = (byte)length;
                    length >>= 8;
                }
                while (length > 0);

                int count = stack.Length - pos;
                stack[--pos] = (byte)(0x80 | count);

                Write(stack, pos, count + 1);
            }
        }

        internal virtual void WriteElements(Asn1Encodable[] elements)
        {
            for (int i = 0, count = elements.Length; i < count; ++i)
            {
                elements[i].ToAsn1Object().Encode(this, true);
            }
        }

        internal void WriteEncodingDL(bool withID, int identifier, byte contents)
        {
            WriteIdentifier(withID, identifier);
            WriteDL(1);
            WriteByte(contents);
        }

        internal void WriteEncodingDL(bool withID, int identifier, byte[] contents)
        {
            WriteIdentifier(withID, identifier);
            WriteDL(contents.Length);
            Write(contents, 0, contents.Length);
        }

        internal void WriteEncodingDL(bool withID, int identifier, byte[] contents, int contentsOff, int contentsLen)
        {
            WriteIdentifier(withID, identifier);
            WriteDL(contentsLen);
            Write(contents, contentsOff, contentsLen);
        }

        internal void WriteEncodingDL(bool withID, int identifier, byte contentsPrefix, byte[] contents,
            int contentsOff, int contentsLen)
        {
            WriteIdentifier(withID, identifier);
            WriteDL(1 + contentsLen);
            WriteByte(contentsPrefix);
            Write(contents, contentsOff, contentsLen);
        }

        internal void WriteEncodingDL(bool withID, int identifier, byte[] contents, int contentsOff, int contentsLen,
            byte contentsSuffix)
        {
            WriteIdentifier(withID, identifier);
            WriteDL(contentsLen + 1);
            Write(contents, contentsOff, contentsLen);
            WriteByte(contentsSuffix);
        }

        internal void WriteEncodingDL(bool withID, int flags, int tag, byte[] contents)
        {
            WriteIdentifier(withID, flags, tag);
            WriteDL(contents.Length);
            Write(contents, 0, contents.Length);
        }

        internal void WriteEncodingIL(bool withID, int identifier, Asn1Encodable[] elements)
        {
            WriteIdentifier(withID, identifier);
            WriteByte(0x80);
            WriteElements(elements);
            WriteByte(0x00);
            WriteByte(0x00);
        }

        internal void WriteIdentifier(bool withID, int identifier)
        {
            if (withID)
            {
                WriteByte((byte)identifier);
            }
        }

        internal void WriteIdentifier(bool withID, int flags, int tag)
        {
            if (!withID)
            {
                // Don't write the identifier
            }
            else if (tag < 31)
            {
                WriteByte((byte)(flags | tag));
            }
            else
            {
                byte[] stack = new byte[6];
                int pos = stack.Length;

                stack[--pos] = (byte)(tag & 0x7F);
                while (tag > 127)
                {
                    tag >>= 7;
                    stack[--pos] = (byte)(tag & 0x7F | 0x80);
                }

                stack[--pos] = (byte)(flags | 0x1F);

                Write(stack, pos, stack.Length - pos);
            }
        }

        internal virtual void WritePrimitive(Asn1Object primitive, bool withID)
        {
            primitive.Encode(this, withID);
        }

        internal virtual void WritePrimitives(Asn1Object[] primitives)
        {
            for (int i = 0, count = primitives.Length; i < count; ++i)
            {
                WritePrimitive(primitives[i], true);
            }
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

        internal static int GetLengthOfEncodingDL(bool withID, int contentsLength)
        {
            return (withID ? 1 : 0) + GetLengthOfDL(contentsLength) + contentsLength;
        }

        internal static int GetLengthOfEncodingDL(bool withID, int tag, int contentsLength)
        {
            return (withID ? GetLengthOfIdentifier(tag) : 0) + GetLengthOfDL(contentsLength) + contentsLength;
        }

        internal static int GetLengthOfIdentifier(int tag)
        {
            if (tag < 31)
                return 1;

            int length = 2;
            while ((tag >>= 7) > 0)
            {
                ++length;
            }
            return length;
        }
    }
}
