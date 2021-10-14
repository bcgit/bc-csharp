using System;
using System.IO;

using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Use 'Asn1OutputStream' instead")]
    public class DerOutputStream
        : FilterStream
    {
        [Obsolete("Use 'Asn1OutputStream.Create' instead")]
        public DerOutputStream(Stream os)
            : base(os)
        {
        }

        public virtual void WriteObject(Asn1Encodable encodable)
        {
            new DerOutputStreamNew(s).WriteObject(encodable);
        }

        public virtual void WriteObject(Asn1Object primitive)
        {
            new DerOutputStreamNew(s).WriteObject(primitive);
        }

        internal virtual bool IsBer
        {
            get { return false; }
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

        internal void WriteEncoded(
			int		tag,
			byte[]	bytes)
		{
			WriteByte((byte)tag);
			WriteDL(bytes.Length);
			Write(bytes, 0, bytes.Length);
		}

        internal void WriteEncoded(
            int     tag,
            byte    first,
            byte[]  bytes)
        {
            WriteByte((byte)tag);
            WriteDL(bytes.Length + 1);
            WriteByte(first);
            Write(bytes, 0, bytes.Length);
        }

        internal void WriteEncoded(
			int		tag,
			byte[]	bytes,
			int		offset,
			int		length)
		{
			WriteByte((byte)tag);
            WriteDL(length);
			Write(bytes, offset, length);
		}

		internal void WriteEncoded(
			int		flags,
			int		tagNo,
			byte[]	bytes)
		{
			WriteIdentifier(true, flags, tagNo);
            WriteDL(bytes.Length);
			Write(bytes, 0, bytes.Length);
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
	}

    internal class DerOutputStreamNew
        : Asn1OutputStream
    {
        internal DerOutputStreamNew(Stream os)
            : base(os)
        {
        }

        internal override bool IsBer
        {
            get { return false; }
        }

        internal override void WritePrimitive(Asn1Object primitive)
        {
            Asn1Set asn1Set = primitive as Asn1Set;
            if (null != asn1Set)
            {
                /*
                 * NOTE: Even a DerSet isn't necessarily already in sorted order (particularly from DerSetParser),
                 * so all sets have to be converted here.
                 */
                primitive = new DerSet(asn1Set.elements);
            }

            primitive.Encode(this);
        }
    }
}
