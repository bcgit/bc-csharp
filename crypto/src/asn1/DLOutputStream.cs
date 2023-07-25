using System;
using System.IO;

namespace Org.BouncyCastle.Asn1
{
    internal class DLOutputStream
        : Asn1OutputStream
    {
        internal DLOutputStream(Stream os, bool leaveOpen)
            : base(os, leaveOpen)
        {
        }

        internal override int Encoding
        {
            get { return EncodingDL; }
        }
    }
}
