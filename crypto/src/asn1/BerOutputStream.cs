using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
	// TODO Make Obsolete in favour of Asn1OutputStream?
    public class BerOutputStream
        : DerOutputStream
    {
        public BerOutputStream(Stream os)
            : base(os)
        {
        }
    }
}
