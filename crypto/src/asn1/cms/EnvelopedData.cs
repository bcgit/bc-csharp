using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The EnvelopedData structure of RFC 5652.</summary>
    public class EnvelopedData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EnvelopedData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EnvelopedData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EnvelopedData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EnvelopedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EnvelopedData envelopedData)
                return envelopedData;
            return new EnvelopedData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EnvelopedData"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EnvelopedData"/>.</returns>
        public static EnvelopedData GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new EnvelopedData(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="EnvelopedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EnvelopedData"/>.</returns>
        public static EnvelopedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EnvelopedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly OriginatorInfo m_originatorInfo;
        private readonly Asn1Set m_recipientInfos;
        private readonly EncryptedContentInfo m_encryptedContentInfo;
        private readonly Asn1Set m_unprotectedAttrs;

        /// <summary>Create a new <see cref="EnvelopedData"/>.</summary>
        /// <param name="originatorInfo">The originator info.</param>
        /// <param name="recipientInfos">The recipient infos.</param>
        /// <param name="encryptedContentInfo">The encrypted content info.</param>
        /// <param name="unprotectedAttrs">The unprotected attrs.</param>
        public EnvelopedData(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
            EncryptedContentInfo encryptedContentInfo, Asn1Set unprotectedAttrs)
        {
            m_version = CalculateVersionField(originatorInfo, recipientInfos, unprotectedAttrs);
            m_originatorInfo = originatorInfo;
            m_recipientInfos = recipientInfos ?? throw new ArgumentNullException(nameof(recipientInfos));
            m_encryptedContentInfo = encryptedContentInfo ?? throw new ArgumentNullException(nameof(encryptedContentInfo));
            m_unprotectedAttrs = unprotectedAttrs;
        }

        /// <summary>Create a new <see cref="EnvelopedData"/>.</summary>
        /// <param name="originatorInfo">The originator info.</param>
        /// <param name="recipientInfos">The recipient infos.</param>
        /// <param name="encryptedContentInfo">The encrypted content info.</param>
        /// <param name="unprotectedAttrs">The unprotected attrs.</param>
        public EnvelopedData(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
            EncryptedContentInfo encryptedContentInfo, Attributes unprotectedAttrs)
            : this(originatorInfo, recipientInfos, encryptedContentInfo, Asn1Set.GetInstance(unprotectedAttrs))
        {
        }

        private EnvelopedData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_originatorInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, OriginatorInfo.GetTagged);
            m_recipientInfos = Asn1Utilities.Read(seq, ref pos, Asn1Set.GetInstance);
            m_encryptedContentInfo = Asn1Utilities.Read(seq, ref pos, EncryptedContentInfo.GetInstance);
            m_unprotectedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the originator info.</summary>
        public OriginatorInfo OriginatorInfo => m_originatorInfo;

        /// <summary>Gets the recipient infos.</summary>
        public Asn1Set RecipientInfos => m_recipientInfos;

        /// <summary>Gets the encrypted content info.</summary>
        public EncryptedContentInfo EncryptedContentInfo => m_encryptedContentInfo;

        /// <summary>Gets the unprotected attrs.</summary>
        public Asn1Set UnprotectedAttrs => m_unprotectedAttrs;

        /// <summary>Produce an object suitable for an <see cref="Asn1OutputStream"/>.</summary>
        /// <remarks>
        /// <code>
        /// EnvelopedData::= Sequence {
        ///     version CMSVersion,
        ///     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        ///     recipientInfos RecipientInfos,
        ///     encryptedContentInfo EncryptedContentInfo,
        ///     unprotectedAttrs[1] IMPLICIT UnprotectedAttributes OPTIONAL
        /// }
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_version);
            v.AddOptionalTagged(false, 0, m_originatorInfo);
            v.Add(m_recipientInfos, m_encryptedContentInfo);
            v.AddOptionalTagged(false, 1, m_unprotectedAttrs);
            return new BerSequence(v);
        }

        public static int CalculateVersion(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
            Asn1Set unprotectedAttrs)
        {
            return CalculateVersionField(originatorInfo, recipientInfos, unprotectedAttrs).IntValueExact;
        }

        private static DerInteger CalculateVersionField(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
            Asn1Set unprotectedAttrs)
        {
            /*
             * IF (originatorInfo is present) AND
             *    ((any certificates with a type of other are present) OR
             *    (any crls with a type of other are present))
             * THEN version is 4
             * ELSE
             *    IF ((originatorInfo is present) AND
             *       (any version 2 attribute certificates are present)) OR
             *       (any RecipientInfo structures include pwri) OR
             *       (any RecipientInfo structures include ori)
             *    THEN version is 3
             *    ELSE
             *       IF (originatorInfo is absent) AND
             *          (unprotectedAttrs is absent) AND
             *          (all RecipientInfo structures are version 0)
             *       THEN version is 0
             *       ELSE version is 2
             */

            int contents = OriginatorInfoContents.Classify(originatorInfo);
            switch (contents)
            {
            case OriginatorInfoContents.Other:
                return DerInteger.Four;
            case OriginatorInfoContents.V2AttributeCertificate:
                return DerInteger.Three;
            default:
                break;
            }

            bool allV0Recipients = true;
            foreach (var element in recipientInfos)
            {
                var recipientInfo = RecipientInfo.GetInstance(element);

                // (any RecipientInfo structures include pwri) OR
                // (any RecipientInfo structures include ori)
                if (recipientInfo.IsPasswordOrOther())
                    return DerInteger.Three;

                // (all RecipientInfo structures are version 0)
                // -- 'kari.version' is always 3
                // -- 'kekri.version' is always 4
                // -- 'pwri' and 'ori' have already been excluded
                allV0Recipients = allV0Recipients && recipientInfo.IsKeyTransV0();
            }

            if (originatorInfo == null && unprotectedAttrs == null && allV0Recipients)
                return DerInteger.Zero;

            return DerInteger.Two;
        }
    }
}
