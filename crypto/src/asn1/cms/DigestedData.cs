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
        /// <summary>Return an <see cref="DigestedData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DigestedData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DigestedData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DigestedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DigestedData digestedData)
                return digestedData;
            return new DigestedData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DigestedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DigestedData"/>.</returns>
        public static DigestedData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DigestedData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="DigestedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DigestedData"/>.</returns>
        public static DigestedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DigestedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly ContentInfo m_encapContentInfo;
        private readonly Asn1OctetString m_digest;

        /// <summary>Create a new <see cref="DigestedData"/>.</summary>
        /// <param name="digestAlgorithm">The digest algorithm.</param>
        /// <param name="encapContentInfo">The encap content info.</param>
        /// <param name="digest">The digest.</param>
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

        /// <summary>Gets the digest.</summary>
        public Asn1OctetString Digest => m_digest;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        /// <summary>Gets the encap content info.</summary>
        public ContentInfo EncapContentInfo => m_encapContentInfo;

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() =>
            new BerSequence(m_version, m_digestAlgorithm, m_encapContentInfo, m_digest);
    }
}
