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

            WritePrimitive(encodable.ToAsn1Object());
            FlushInternal();
        }

        public override void WriteObject(Asn1Object primitive)
        {
            if (null == primitive)
                throw new IOException("null object detected");

            WritePrimitive(primitive);
            FlushInternal();
        }

        internal void FlushInternal()
        {
            // Placeholder to support future internal buffering
        }

        internal override bool IsBer
        {
            get { return true; }
        }

        internal virtual void WriteElements(Asn1Encodable[] elements)
        {
            for (int i = 0, count = elements.Length; i < count; ++i)
            {
                elements[i].ToAsn1Object().Encode(this);
            }
        }

        internal virtual void WritePrimitive(Asn1Object primitive)
        {
            primitive.Encode(this);
        }

        internal virtual void WritePrimitives(Asn1Object[] primitives)
        {
            for (int i = 0, count = primitives.Length; i < count; ++i)
            {
                WritePrimitive(primitives[i]);
            }
        }
    }
}
