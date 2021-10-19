using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Use 'Asn1OutputStream' instead")]
    public class BerOutputStream
        : DerOutputStream
    {
        [Obsolete("Use 'Asn1OutputStream.Create' instead")]
        public BerOutputStream(Stream os)
            : base(os)
        {
        }

        public override void WriteObject(Asn1Encodable encodable)
        {
            Asn1OutputStream.Create(s).WriteObject(encodable);
        }

        public override void WriteObject(Asn1Object primitive)
        {
            Asn1OutputStream.Create(s).WriteObject(primitive);
        }
    }
}
