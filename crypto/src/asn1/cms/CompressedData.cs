using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /**
     * RFC 3274 - CMS Compressed Data.
     * <pre>
     * CompressedData ::= Sequence {
     *  version CMSVersion,
     *  compressionAlgorithm CompressionAlgorithmIdentifier,
     *  encapContentInfo EncapsulatedContentInfo
     * }
     * </pre>
     */
    public class CompressedData
        : Asn1Encodable
    {
        public static CompressedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CompressedData compressedData)
                return compressedData;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CompressedData(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static CompressedData GetInstance(Asn1TaggedObject ato, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CompressedData(Asn1Sequence.GetInstance(ato, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private DerInteger			version;
        private AlgorithmIdentifier	compressionAlgorithm;
        private ContentInfo			encapContentInfo;

		public CompressedData(
            AlgorithmIdentifier	compressionAlgorithm,
            ContentInfo			encapContentInfo)
        {
            this.version = DerInteger.Zero;
            this.compressionAlgorithm = compressionAlgorithm;
            this.encapContentInfo = encapContentInfo;
        }

        [Obsolete("Use 'GetInstance' instead")]
        public CompressedData(
            Asn1Sequence seq)
        {
            this.version = (DerInteger) seq[0];
            this.compressionAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
            this.encapContentInfo = ContentInfo.GetInstance(seq[2]);
        }

        public DerInteger Version
		{
			get { return version; }
		}

		public AlgorithmIdentifier CompressionAlgorithmIdentifier
		{
			get { return compressionAlgorithm; }
		}

		public ContentInfo EncapContentInfo
		{
			get { return encapContentInfo; }
		}

		public override Asn1Object ToAsn1Object()
        {
			return new BerSequence(version, compressionAlgorithm, encapContentInfo);
        }
    }
}
