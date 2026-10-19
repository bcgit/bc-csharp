using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Generator that writes a BER SET to a stream piece by piece.</summary>
    public class BerSetGenerator
        : BerGenerator
    {
        /// <summary>Create a new <see cref="BerSetGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        public BerSetGenerator(Stream outStream)
            : base(outStream)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.Set);
        }

        /// <summary>Create a new <see cref="BerSetGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        /// <param name="tagNo">The tag no.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        public BerSetGenerator(Stream outStream, int tagNo, bool isExplicit)
            : base(outStream, tagNo, isExplicit)
        {
            WriteBerHeader(Asn1Tags.Constructed | Asn1Tags.Set);
        }
    }
}
