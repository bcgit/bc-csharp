using System;

using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of the Archive Timestamp type defined in RFC4998.
     * @see <a href="https://tools.ietf.org/html/rfc4998">RFC 4998</a>
     * <p>
     * ASN.1 Archive Timestamp
     * <p>
     * ArchiveTimeStamp ::= SEQUENCE {
     * digestAlgorithm [Ø] AlgorithmIdentifier OPTIONAL,
     * attributes      [1] Attributes OPTIONAL,
     * reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
     * timeStamp       ContentInfo}
     * <p>
     * PartialHashtree ::= SEQUENCE OF OCTET STRING
     * <p>
     * Attributes ::= SET SIZE (1..MAX) OF Attribute
     */
    public class ArchiveTimeStamp
        : Asn1Encodable
    {
        /**
         * Return an ArchiveTimestamp from the given object.
         *
         * @param obj the object we want converted.
         * @return an ArchiveTimestamp instance, or null.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        public static ArchiveTimeStamp GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ArchiveTimeStamp archiveTimeStamp)
                return archiveTimeStamp;
            return new ArchiveTimeStamp(Asn1Sequence.GetInstance(obj));
        }

        public static ArchiveTimeStamp GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ArchiveTimeStamp(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly Attributes m_attributes;
        private readonly Asn1Sequence m_reducedHashTree;
        private readonly ContentInfo m_timeStamp;

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
            if (reducedHashTree != null)
            {
                m_reducedHashTree = new DerSequence(reducedHashTree);
            }
            else
            {
                m_reducedHashTree = null;
            }
            m_timeStamp = timeStamp;
        }

        private ArchiveTimeStamp(Asn1Sequence sequence)
        {
            if (sequence.Count < 1 || sequence.Count > 4)
                throw new ArgumentException("wrong sequence size in constructor: " + sequence.Count, nameof(sequence));

            AlgorithmIdentifier digAlg = null;
            Attributes attrs = null;
            Asn1Sequence rHashTree = null;
            for (int i = 0; i < sequence.Count - 1; i++)
            {
                Asn1Encodable obj = sequence[i];

                if (obj is Asn1TaggedObject taggedObject)
                {
                    switch (taggedObject.TagNo)
                    {
                    case 0:
                        digAlg = AlgorithmIdentifier.GetInstance(taggedObject, false);
                        break;
                    case 1:
                        attrs = Attributes.GetInstance(taggedObject, false);
                        break;
                    case 2:
                        rHashTree = Asn1Sequence.GetInstance(taggedObject, false);
                        break;
                    default:
                        throw new ArgumentException("invalid tag no in constructor: " + taggedObject.TagNo);
                    }
                }
            }

            m_digestAlgorithm = digAlg;
            m_attributes = attrs;
            m_reducedHashTree = rHashTree;
            m_timeStamp = ContentInfo.GetInstance(sequence[sequence.Count - 1]);
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

        public virtual PartialHashtree[] GetReducedHashTree()
        {
            if (m_reducedHashTree == null)
                return null;

            return m_reducedHashTree.MapElements(PartialHashtree.GetInstance);
        }

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
