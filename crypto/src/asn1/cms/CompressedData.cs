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
        /// <summary>Return an <see cref="CompressedData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CompressedData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CompressedData"/>, or null if <paramref name="obj"/> is null.</returns>
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

        /// <summary>Return an <see cref="CompressedData"/> from a tagged object.</summary>
        /// <param name="ato">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CompressedData"/>.</returns>
        public static CompressedData GetInstance(Asn1TaggedObject ato, bool explicitly)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CompressedData(Asn1Sequence.GetInstance(ato, explicitly));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CompressedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CompressedData"/>.</returns>
        public static CompressedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CompressedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_compressionAlgorithm;
        private readonly ContentInfo m_encapContentInfo;

        /// <summary>Create a new <see cref="CompressedData"/>.</summary>
        /// <param name="compressionAlgorithm">The compression algorithm.</param>
        /// <param name="encapContentInfo">The encap content info.</param>
        public CompressedData(AlgorithmIdentifier compressionAlgorithm, ContentInfo encapContentInfo)
        {
            m_version = DerInteger.Zero;
            m_compressionAlgorithm = compressionAlgorithm ?? throw new ArgumentNullException(nameof(compressionAlgorithm));
            m_encapContentInfo = encapContentInfo ?? throw new ArgumentNullException(nameof(encapContentInfo));
        }

        /// <summary>Create a new <see cref="CompressedData"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public CompressedData(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_compressionAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_encapContentInfo = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the compression algorithm identifier.</summary>
        public AlgorithmIdentifier CompressionAlgorithmIdentifier => m_compressionAlgorithm;

        /// <summary>Gets the encap content info.</summary>
        public ContentInfo EncapContentInfo => m_encapContentInfo;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() =>
            new BerSequence(m_version, m_compressionAlgorithm, m_encapContentInfo);
    }
}
