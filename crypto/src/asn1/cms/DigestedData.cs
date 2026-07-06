using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>
    /// The <see href="https://tools.ietf.org/html/rfc5652#section-7">RFC 5652</see> DigestedData object.
    /// </summary>
    /// <remarks>
    /// <code>
    /// DigestedData ::= SEQUENCE {
    ///     version CMSVersion,
    ///     digestAlgorithm DigestAlgorithmIdentifier,
    ///     encapContentInfo EncapsulatedContentInfo,
    ///     digest Digest
    /// }
    /// </code>
    /// </remarks>
    public sealed class DigestedData
        : Asn1Encodable
    {
        public static DigestedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DigestedData digestedData)
                return digestedData;
            return new DigestedData(Asn1Sequence.GetInstance(obj));
        }

        public static DigestedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DigestedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static DigestedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DigestedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly ContentInfo m_encapContentInfo;
        private readonly Asn1OctetString m_digest;

        public DigestedData(AlgorithmIdentifier digestAlgorithm, ContentInfo encapContentInfo, Asn1OctetString digest)
        {
            m_version = DerInteger.Zero;
            m_digestAlgorithm = digestAlgorithm;
            m_encapContentInfo = encapContentInfo;
            m_digest = digest;
        }

        private DigestedData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_digestAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encapContentInfo = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);
            m_digest = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public Asn1OctetString Digest => m_digest;

        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        public ContentInfo EncapContentInfo => m_encapContentInfo;

        public DerInteger Version => m_version;

        public override Asn1Object ToAsn1Object() =>
            new BerSequence(m_version, m_digestAlgorithm, m_encapContentInfo, m_digest);
    }
}
