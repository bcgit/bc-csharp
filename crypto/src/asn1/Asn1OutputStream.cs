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

        public override void WriteObject(Asn1Encodable obj)
        {
            if (obj == null)
            {
                WriteNull();
            }
            else
            {
                obj.ToAsn1Object().Encode(this);
            }
        }

        public override void WriteObject(Asn1Object obj)
        {
            if (obj == null)
            {
                WriteNull();
            }
            else
            {
                obj.Encode(this);
            }
        }
    }
}
