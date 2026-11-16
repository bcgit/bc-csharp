using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The DigestInfo object.
     * <pre>
     * DigestInfo::=Sequence{
     *          digestAlgorithm  AlgorithmIdentifier,
     *          digest OCTET STRING }
     * </pre>
     */
    public class DigestInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DigestInfo"/> from the given object.</summary>
        /// <param name="obj">An <see cref="DigestInfo"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="DigestInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DigestInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DigestInfo digestInfo)
                return digestInfo;
            return new DigestInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DigestInfo"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DigestInfo"/>.</returns>
        public static DigestInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new DigestInfo(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="DigestInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DigestInfo"/>.</returns>
        public static DigestInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DigestInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly Asn1OctetString m_digest;

        private DigestInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digestAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_digest = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="DigestInfo"/>.</summary>
        /// <param name="algID">The alg ID.</param>
        /// <param name="digest">The digest.</param>
        // TODO[api] 'algID' => 'digestAlgorithm'
        public DigestInfo(AlgorithmIdentifier algID, byte[] digest)
        {
            m_digestAlgorithm = algID ?? throw new ArgumentNullException(nameof(algID));
            m_digest = DerOctetString.FromContents(digest);
        }

        /// <summary>Create a new <see cref="DigestInfo"/>.</summary>
        /// <param name="digestAlgorithm">The digest algorithm.</param>
        /// <param name="digest">The digest.</param>
        public DigestInfo(AlgorithmIdentifier digestAlgorithm, Asn1OctetString digest)
        {
            m_digestAlgorithm = digestAlgorithm ?? throw new ArgumentNullException(nameof(digestAlgorithm));
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));
        }

        /// <summary>Gets the algorithm ID.</summary>
        [Obsolete("Use 'DigestAlgorithm' property instead")]
        public AlgorithmIdentifier AlgorithmID => m_digestAlgorithm;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        /// <summary>Gets the digest.</summary>
        public Asn1OctetString Digest => m_digest;

        /// <summary>Return the digest.</summary>
        [Obsolete("Use 'Digest' property instead")]
        public byte[] GetDigest() => Arrays.Clone(m_digest.GetOctets());

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_digestAlgorithm, m_digest);
    }
}
