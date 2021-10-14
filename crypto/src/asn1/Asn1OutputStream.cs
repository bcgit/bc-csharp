using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    public class Asn1OutputStream
        : DerOutputStream
    {
        public Asn1OutputStream(Stream os)
            : base(os)
        {
        }
    }
}
