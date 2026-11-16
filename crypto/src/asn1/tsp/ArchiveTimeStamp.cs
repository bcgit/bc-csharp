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
        /// <summary>Return an <see cref="ArchiveTimeStamp"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ArchiveTimeStamp"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ArchiveTimeStamp"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ArchiveTimeStamp GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ArchiveTimeStamp archiveTimeStamp)
                return archiveTimeStamp;
            return new ArchiveTimeStamp(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ArchiveTimeStamp"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ArchiveTimeStamp"/>.</returns>
        public static ArchiveTimeStamp GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ArchiveTimeStamp(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ArchiveTimeStamp"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ArchiveTimeStamp"/>.</returns>
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
            m_timeStamp = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="ArchiveTimeStamp"/>.</summary>
        /// <param name="digestAlgorithm">The digest algorithm.</param>
        /// <param name="reducedHashTree">The reduced hash tree.</param>
        /// <param name="timeStamp">The time stamp.</param>
        public ArchiveTimeStamp(AlgorithmIdentifier digestAlgorithm, PartialHashtree[] reducedHashTree,
            ContentInfo timeStamp)
            : this(digestAlgorithm, null, reducedHashTree, timeStamp)
        {
        }

        /// <summary>Create a new <see cref="ArchiveTimeStamp"/>.</summary>
        /// <param name="timeStamp">The time stamp.</param>
        public ArchiveTimeStamp(ContentInfo timeStamp)
            : this(null, null, null, timeStamp)
        {
        }

        /// <summary>Create a new <see cref="ArchiveTimeStamp"/>.</summary>
        /// <param name="digestAlgorithm">The digest algorithm.</param>
        /// <param name="attributes">The attributes.</param>
        /// <param name="reducedHashTree">The reduced hash tree.</param>
        /// <param name="timeStamp">The time stamp.</param>
        public ArchiveTimeStamp(AlgorithmIdentifier digestAlgorithm, Attributes attributes,
            PartialHashtree[] reducedHashTree, ContentInfo timeStamp)
        {
            m_digestAlgorithm = digestAlgorithm;
            m_attributes = attributes;
            m_reducedHashTree = reducedHashTree == null ? null : new DerSequence(reducedHashTree);
            m_timeStamp = timeStamp ?? throw new ArgumentNullException(nameof(timeStamp));
        }

        /// <summary>Return the digest algorithm identifier.</summary>
        public virtual AlgorithmIdentifier GetDigestAlgorithmIdentifier() => m_digestAlgorithm
            ?? GetTimeStampInfo().MessageImprint.HashAlgorithm;

        /// <summary>Return the time stamp digest value.</summary>
        public virtual byte[] GetTimeStampDigestValue() => GetTimeStampInfo().MessageImprint.GetHashedMessage();

        private TstInfo GetTimeStampInfo()
        {
            if (!CmsObjectIdentifiers.SignedData.Equals(m_timeStamp.ContentType))
                throw new InvalidOperationException("cannot identify algorithm identifier for digest");

            var tsData = SignedData.GetInstance(m_timeStamp.Content);
            var encapContentInfo = tsData.EncapContentInfo;

            if (!Asn1.Pkcs.PkcsObjectIdentifiers.IdCTTstInfo.Equals(encapContentInfo.ContentType))
                throw new InvalidOperationException("cannot parse time stamp");

            var encapContent = Asn1OctetString.GetInstance(encapContentInfo.Content);

            return TstInfo.GetInstance(encapContent.GetOctets());
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

        /// <summary>Return the reduced hash tree.</summary>
        public virtual PartialHashtree[] GetReducedHashTree() =>
            m_reducedHashTree?.MapElements(PartialHashtree.GetInstance);

        /// <summary>Gets the time stamp.</summary>
        public virtual ContentInfo TimeStamp => m_timeStamp;

        /// <inheritdoc/>
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
