using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class EnvelopedData
        : Asn1Encodable
    {
        public static EnvelopedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EnvelopedData envelopedData)
                return envelopedData;
            return new EnvelopedData(Asn1Sequence.GetInstance(obj));
        }

        public static EnvelopedData GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return new EnvelopedData(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly DerInteger m_version;
        private readonly OriginatorInfo m_originatorInfo;
        private readonly Asn1Set m_recipientInfos;
        private readonly EncryptedContentInfo m_encryptedContentInfo;
        private readonly Asn1Set m_unprotectedAttrs;

        public EnvelopedData(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
            EncryptedContentInfo encryptedContentInfo, Asn1Set unprotectedAttrs)
        {
            m_version = CalculateVersionField(originatorInfo, recipientInfos, unprotectedAttrs);
            m_originatorInfo = originatorInfo;
            m_recipientInfos = recipientInfos ?? throw new ArgumentNullException(nameof(recipientInfos));
            m_encryptedContentInfo = encryptedContentInfo ?? throw new ArgumentNullException(nameof(encryptedContentInfo));
            m_unprotectedAttrs = unprotectedAttrs;
        }

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

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_originatorInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, OriginatorInfo.GetTagged);
            m_recipientInfos = Asn1Set.GetInstance(seq[pos++]);
            m_encryptedContentInfo = EncryptedContentInfo.GetInstance(seq[pos++]);
            m_unprotectedAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DerInteger Version => m_version;

        public OriginatorInfo OriginatorInfo => m_originatorInfo;

        public Asn1Set RecipientInfos => m_recipientInfos;

        public EncryptedContentInfo EncryptedContentInfo => m_encryptedContentInfo;

        public Asn1Set UnprotectedAttrs => m_unprotectedAttrs;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * EnvelopedData ::= Sequence {
         *     version CMSVersion,
         *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
         *     recipientInfos RecipientInfos,
         *     encryptedContentInfo EncryptedContentInfo,
         *     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
         * }
         * </pre>
         */
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

            if (originatorInfo != null)
            {
                var crls = originatorInfo.Crls;
                if (crls != null)
                {
                    foreach (var element in crls)
                    {
                        var tagged = Asn1TaggedObject.GetOptional(element);
                        if (tagged != null)
                        {
                            // RevocationInfoChoice.other
                            if (tagged.HasContextTag(1))
                                return DerInteger.Four;
                        }
                    }
                }

                var certs = originatorInfo.Certificates;
                if (certs != null)
                {
                    bool anyV2AttrCerts = false;

                    foreach (var element in certs)
                    {
                        var tagged = Asn1TaggedObject.GetOptional(element);
                        if (tagged != null)
                        {
                            // CertificateChoices.other
                            if (tagged.HasContextTag(3))
                                return DerInteger.Four;

                            // CertificateChoices.v2AttrCert
                            anyV2AttrCerts = anyV2AttrCerts || tagged.HasContextTag(2);
                        }
                    }

                    if (anyV2AttrCerts)
                        return DerInteger.Three;
                }
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
