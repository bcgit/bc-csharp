using System.IO;

namespace Org.BouncyCastle.Asn1
{
    /// <summary>Generator that writes a DER SET to a stream piece by piece.</summary>
    public class DerSetGenerator
        : DerGenerator
    {
        private readonly MemoryStream _bOut = new MemoryStream();

        /// <summary>Create a new <see cref="DerSetGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        public DerSetGenerator(Stream outStream)
            : base(outStream)
        {
        }

        /// <summary>Create a new <see cref="DerSetGenerator"/>.</summary>
        /// <param name="outStream">The output stream.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        public DerSetGenerator(Stream outStream, int tagNo, bool isExplicit)
            : base(outStream, tagNo, isExplicit)
        {
        }

        /// <inheritdoc/>
        protected override void Finish()
        {
            WriteDerEncoded(Asn1Tags.Constructed | Asn1Tags.Set, _bOut.ToArray());
        }

        /// <inheritdoc/>
        public override void AddObject(Asn1Encodable obj)
        {
            obj.EncodeTo(_bOut, Asn1Encodable.Der);
        }

        /// <inheritdoc/>
        public override void AddObject(Asn1Object obj)
        {
            obj.EncodeTo(_bOut, Asn1Encodable.Der);
        }

        /// <inheritdoc/>
        public override Stream GetRawOutputStream()
        {
            return _bOut;
        }
    }
}
