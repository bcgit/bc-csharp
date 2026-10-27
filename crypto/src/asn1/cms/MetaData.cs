using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The MetaData structure of RFC 5544.</summary>
    public class MetaData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="MetaData"/> from the given object.</summary>
        /// <param name="obj">An <see cref="MetaData"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="MetaData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static MetaData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MetaData metaData)
                return metaData;
            return new MetaData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="MetaData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MetaData"/>.</returns>
        public static MetaData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MetaData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="MetaData"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="MetaData"/>, or null if <paramref name="element"/> is null.</returns>
        public static MetaData GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is MetaData metaData)
                return metaData;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new MetaData(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="MetaData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="MetaData"/>.</returns>
        public static MetaData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MetaData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerBoolean m_hashProtected;
        private readonly DerUtf8String m_fileName;
        private readonly DerIA5String m_mediaType;
        private readonly Attributes m_otherMetaData;

        /// <summary>Create a new <see cref="MetaData"/>.</summary>
        /// <param name="hashProtected">The hash protected.</param>
        /// <param name="fileName">The file name.</param>
        /// <param name="mediaType">The media type.</param>
        /// <param name="otherMetaData">The other meta data.</param>
        public MetaData(DerBoolean hashProtected, DerUtf8String fileName, DerIA5String mediaType,
            Attributes otherMetaData)
        {
            m_hashProtected = hashProtected ?? throw new ArgumentNullException(nameof(hashProtected));
            m_fileName = fileName;
            m_mediaType = mediaType;
            m_otherMetaData = otherMetaData;
        }

        private MetaData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashProtected = Asn1Utilities.Read(seq, ref pos, DerBoolean.GetInstance);
            m_fileName = Asn1Utilities.ReadOptional(seq, ref pos, DerUtf8String.GetOptional);
            m_mediaType = Asn1Utilities.ReadOptional(seq, ref pos, DerIA5String.GetOptional);
            m_otherMetaData = Asn1Utilities.ReadOptional(seq, ref pos, Attributes.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets a value indicating whether this is hash protected.</summary>
        public virtual bool IsHashProtected => m_hashProtected.IsTrue;

        /// <summary>Gets the file name.</summary>
        public virtual DerUtf8String FileName => m_fileName;

        /// <summary>Gets the media type.</summary>
        public virtual DerIA5String MediaType => m_mediaType;

        /// <summary>Gets the other meta data.</summary>
        public virtual Attributes OtherMetaData => m_otherMetaData;

        /// <remarks>
        /// <code>
        /// MetaData::= SEQUENCE {
        ///     hashProtected   BOOLEAN,
        ///     fileName        UTF8String OPTIONAL,
        ///     mediaType       IA5String OPTIONAL,
        ///     otherMetaData   Attributes OPTIONAL
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_hashProtected);
            v.AddOptional(m_fileName, m_mediaType, m_otherMetaData);
            return new DerSequence(v);
        }
    }
}
