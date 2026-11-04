using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Generator that writes a BER SEQUENCE to a stream piece by piece.</summary>
    public class BerSequenceGenerator
        : BerGenerator
    {
        /// <summary>Create a new <see cref="BerSequenceGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        public BerSequenceGenerator(Stream outStream)
            : base(outStream)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.Sequence);
        }

        /// <summary>Create a new <see cref="BerSequenceGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        public BerSequenceGenerator(Stream outStream, int tagNo, bool isExplicit)
            : base(outStream, tagNo, isExplicit)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.Sequence);
        }
    }
}
