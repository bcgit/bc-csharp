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

        public static CompressedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CompressedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_compressionAlgorithm;
        private readonly ContentInfo m_encapContentInfo;

        public CompressedData(AlgorithmIdentifier compressionAlgorithm, ContentInfo encapContentInfo)
        {
            m_version = DerInteger.Zero;
            m_compressionAlgorithm = compressionAlgorithm ?? throw new ArgumentNullException(nameof(compressionAlgorithm));
            m_encapContentInfo = encapContentInfo ?? throw new ArgumentNullException(nameof(encapContentInfo));
        }

        [Obsolete("Use 'GetInstance' instead")]
        public CompressedData(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[0]);
            m_compressionAlgorithm = AlgorithmIdentifier.GetInstance(seq[1]);
            m_encapContentInfo = ContentInfo.GetInstance(seq[2]);
        }

        public DerInteger Version => m_version;

        public AlgorithmIdentifier CompressionAlgorithmIdentifier => m_compressionAlgorithm;

        public ContentInfo EncapContentInfo => m_encapContentInfo;

		public override Asn1Object ToAsn1Object() =>
            new BerSequence(m_version, m_compressionAlgorithm, m_encapContentInfo);
    }
}
