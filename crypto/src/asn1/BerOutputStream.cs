using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    [Obsolete("Use 'Asn1OutputStream' instead")]
    public class BerOutputStream
        : DerOutputStream
    {
        public BerOutputStream(Stream os)
            : base(os)
        {
        }

        internal override bool IsBer
        {
            get { return true; }
        }
    }
}
