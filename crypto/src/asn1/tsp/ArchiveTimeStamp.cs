using System;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the Archive Timestamp type defined in RFC4998.
     * @see <a href="https://tools.ietf.org/html/rfc4998">RFC 4998</a>
     * <p/>
     * ASN.1 Archive Timestamp
     * <p/>
     * ArchiveTimeStamp ::= SEQUENCE {
     * digestAlgorithm [Ø] AlgorithmIdentifier OPTIONAL,
     * attributes      [1] Attributes OPTIONAL,
     * reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
     * timeStamp       ContentInfo}
     * <p/>
     * PartialHashtree ::= SEQUENCE OF OCTET STRING
     * <p/>
     * Attributes ::= SET SIZE (1..MAX) OF Attribute
     */
    public class ArchiveTimeStamp
        : Asn1Encodable
    {
        public static ArchiveTimeStamp GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ArchiveTimeStamp archiveTimeStamp)
                return archiveTimeStamp;
            return new ArchiveTimeStamp(Asn1Sequence.GetInstance(obj));
        }

        public static ArchiveTimeStamp GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ArchiveTimeStamp(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ArchiveTimeStamp GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ArchiveTimeStamp(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly Attributes m_attributes;
        private readonly Asn1Sequence m_reducedHashTree;
        private readonly ContentInfo m_timeStamp;

        private ArchiveTimeStamp(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digestAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, AlgorithmIdentifier.GetTagged);
            m_attributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Attributes.GetTagged);
            m_reducedHashTree = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, Asn1Sequence.GetTagged);
            m_timeStamp = ContentInfo.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public ArchiveTimeStamp(AlgorithmIdentifier digestAlgorithm, PartialHashtree[] reducedHashTree,
            ContentInfo timeStamp)
            : this(digestAlgorithm, null, reducedHashTree, timeStamp)
        {
        }

        public ArchiveTimeStamp(ContentInfo timeStamp)
            : this(null, null, null, timeStamp)
        {
        }

        public ArchiveTimeStamp(AlgorithmIdentifier digestAlgorithm, Attributes attributes,
            PartialHashtree[] reducedHashTree, ContentInfo timeStamp)
        {
            m_digestAlgorithm = digestAlgorithm;
            m_attributes = attributes;
            m_reducedHashTree = reducedHashTree == null ? null : new DerSequence(reducedHashTree);
            m_timeStamp = timeStamp ?? throw new ArgumentNullException(nameof(timeStamp));
        }

        public virtual AlgorithmIdentifier GetDigestAlgorithmIdentifier() => m_digestAlgorithm
            ?? GetTimeStampInfo().MessageImprint.HashAlgorithm;

        public virtual byte[] GetTimeStampDigestValue() => GetTimeStampInfo().MessageImprint.GetHashedMessage();

        private TstInfo GetTimeStampInfo()
        {
            if (!CmsObjectIdentifiers.SignedData.Equals(m_timeStamp.ContentType))
                throw new InvalidOperationException("cannot identify algorithm identifier for digest");

            SignedData tsData = SignedData.GetInstance(m_timeStamp.Content);
            var contentInfo = tsData.EncapContentInfo;

            if (!Asn1.Pkcs.PkcsObjectIdentifiers.IdCTTstInfo.Equals(contentInfo.ContentType))
                throw new InvalidOperationException("cannot parse time stamp");

            return TstInfo.GetInstance(Asn1OctetString.GetInstance(contentInfo.Content).GetOctets());
        }

        /**
         * Return the contents of the digestAlgorithm field - null if not set.
         *
         * @return the contents of the digestAlgorithm field, or null if not set.
         */
        public virtual AlgorithmIdentifier DigestAlgorithm() => m_digestAlgorithm;

        /**
         * Return the first node in the reduced hash tree which contains the leaf node.
         *
         * @return the node containing the data hashes, null if no reduced hash tree is present.
         */
        public virtual PartialHashtree GetHashTreeLeaf()
        {
            if (m_reducedHashTree == null)
                return null;

            return PartialHashtree.GetInstance(m_reducedHashTree[0]);
        }

        public virtual PartialHashtree[] GetReducedHashTree() =>
            m_reducedHashTree?.MapElements(PartialHashtree.GetInstance);

        public virtual ContentInfo TimeStamp => m_timeStamp;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.AddOptionalTagged(false, 0, m_digestAlgorithm);
            v.AddOptionalTagged(false, 1, m_attributes);
            v.AddOptionalTagged(false, 2, m_reducedHashTree);
            v.Add(m_timeStamp);
            return new DerSequence(v);
        }
    }
}
