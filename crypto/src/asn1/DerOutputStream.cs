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
            Asn1OutputStream.Create(s, Asn1Encodable.Der).WriteObject(encodable);
        }

        public virtual void WriteObject(Asn1Object primitive)
        {
            Asn1OutputStream.Create(s, Asn1Encodable.Der).WriteObject(primitive);
        }
	}

    internal class DerOutputStreamNew
        : Asn1OutputStream
    {
        internal DerOutputStreamNew(Stream os)
            : base(os)
        {
        }

        internal override int Encoding
        {
            get { return EncodingDer; }
        }
    }
}
