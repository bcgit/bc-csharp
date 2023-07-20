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

        private DerInteger				version;
        private OriginatorInfo			originatorInfo;
        private Asn1Set					recipientInfos;
        private EncryptedContentInfo	encryptedContentInfo;
        private Asn1Set					unprotectedAttrs;

        public EnvelopedData(
            OriginatorInfo			originatorInfo,
            Asn1Set					recipientInfos,
            EncryptedContentInfo	encryptedContentInfo,
            Asn1Set					unprotectedAttrs)
        {
            this.version = new DerInteger(CalculateVersion(originatorInfo, recipientInfos, unprotectedAttrs));
            this.originatorInfo = originatorInfo;
            this.recipientInfos = recipientInfos;
            this.encryptedContentInfo = encryptedContentInfo;
            this.unprotectedAttrs = unprotectedAttrs;
        }

        public EnvelopedData(
            OriginatorInfo originatorInfo,
            Asn1Set recipientInfos,
            EncryptedContentInfo encryptedContentInfo,
            Attributes unprotectedAttrs)
        {
            this.version = new DerInteger(CalculateVersion(originatorInfo, recipientInfos, Asn1Set.GetInstance(unprotectedAttrs)));
            this.originatorInfo = originatorInfo;
            this.recipientInfos = recipientInfos;
            this.encryptedContentInfo = encryptedContentInfo;
            this.unprotectedAttrs = Asn1Set.GetInstance(unprotectedAttrs);
        }

        private EnvelopedData(Asn1Sequence seq)
        {
            int index = 0;

            version = (DerInteger) seq[index++];

            object tmp = seq[index++];

            if (tmp is Asn1TaggedObject taggedObject)
            {
                originatorInfo = OriginatorInfo.GetInstance(taggedObject, false);
                tmp = seq[index++];
            }

            recipientInfos = Asn1Set.GetInstance(tmp);
            encryptedContentInfo = EncryptedContentInfo.GetInstance(seq[index++]);

            if (seq.Count > index)
            {
                unprotectedAttrs = Asn1Set.GetInstance((Asn1TaggedObject)seq[index], false);
            }
        }

        public DerInteger Version
        {
            get { return version; }
        }

        public OriginatorInfo OriginatorInfo
        {
            get { return originatorInfo; }
        }

        public Asn1Set RecipientInfos
        {
            get { return recipientInfos; }
        }

        public EncryptedContentInfo EncryptedContentInfo
        {
            get { return encryptedContentInfo; }
        }

        public Asn1Set UnprotectedAttrs
        {
            get { return unprotectedAttrs; }
        }

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
            Asn1EncodableVector v = new Asn1EncodableVector(version);
            v.AddOptionalTagged(false, 0, originatorInfo);
            v.Add(recipientInfos, encryptedContentInfo);
            v.AddOptionalTagged(false, 1, unprotectedAttrs);
            return new BerSequence(v);
        }

        public static int CalculateVersion(OriginatorInfo originatorInfo, Asn1Set recipientInfos, Asn1Set unprotectedAttrs)
        {
            if (originatorInfo != null || unprotectedAttrs != null)
            {
                return 2;
            }

            foreach (object o in recipientInfos)
            {
                RecipientInfo ri = RecipientInfo.GetInstance(o);

                if (!ri.Version.HasValue(0))
                {
                    return 2;
                }
            }

            return 0;
        }
    }
}
