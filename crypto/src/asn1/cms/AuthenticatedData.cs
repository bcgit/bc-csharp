using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class AuthenticatedData
		: Asn1Encodable
	{
        public static AuthenticatedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthenticatedData authenticatedData)
                return authenticatedData;
            return new AuthenticatedData(Asn1Sequence.GetInstance(obj));
        }

        public static AuthenticatedData GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new AuthenticatedData(Asn1Sequence.GetInstance(obj, isExplicit));

        public static AuthenticatedData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthenticatedData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly OriginatorInfo m_originatorInfo;
        private readonly Asn1Set m_recipientInfos;
        private readonly AlgorithmIdentifier m_macAlgorithm;
        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly ContentInfo m_encapsulatedContentInfo;
        private readonly Asn1Set m_authAttrs;
        private readonly Asn1OctetString m_mac;
        private readonly Asn1Set m_unauthAttrs;

        public AuthenticatedData(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
			AlgorithmIdentifier macAlgorithm, AlgorithmIdentifier digestAlgorithm, ContentInfo encapsulatedContent,
            Asn1Set authAttrs, Asn1OctetString mac, Asn1Set unauthAttrs)
        {
            if ((digestAlgorithm == null) != (authAttrs == null))
                throw new ArgumentException("digestAlgorithm and authAttrs must be set together");

            m_version = CalculateVersionField(originatorInfo);
            m_originatorInfo = originatorInfo;
            m_macAlgorithm = macAlgorithm ?? throw new ArgumentNullException(nameof(macAlgorithm));
            m_digestAlgorithm = digestAlgorithm;
            m_recipientInfos = recipientInfos ?? throw new ArgumentNullException(nameof(recipientInfos));
            m_encapsulatedContentInfo = encapsulatedContent ?? throw new ArgumentNullException(nameof(encapsulatedContent));
            m_authAttrs = authAttrs;
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
            m_unauthAttrs = unauthAttrs;
        }

        private AuthenticatedData(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 5 || count > 9)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_originatorInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, OriginatorInfo.GetTagged);
            m_recipientInfos = Asn1Set.GetInstance(seq[pos++]);
            m_macAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_digestAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, AlgorithmIdentifier.GetTagged);
            m_encapsulatedContentInfo = ContentInfo.GetInstance(seq[pos++]);
            m_authAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, Asn1Set.GetTagged);
            m_mac = Asn1OctetString.GetInstance(seq[pos++]);
            m_unauthAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
		}

        public DerInteger Version => m_version;

        public OriginatorInfo OriginatorInfo => m_originatorInfo;

        public Asn1Set RecipientInfos => m_recipientInfos;

        public AlgorithmIdentifier MacAlgorithm => m_macAlgorithm;

        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        public ContentInfo EncapsulatedContentInfo => m_encapsulatedContentInfo;

        public Asn1Set AuthAttrs => m_authAttrs;

        public Asn1OctetString Mac => m_mac;

        public Asn1Set UnauthAttrs => m_unauthAttrs;

        /**
		 * Produce an object suitable for an Asn1OutputStream.
		 * <pre>
		 * AuthenticatedData ::= SEQUENCE {
		 *       version CMSVersion,
		 *       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
		 *       recipientInfos RecipientInfos,
		 *       macAlgorithm MessageAuthenticationCodeAlgorithm,
		 *       digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
		 *       encapContentInfo EncapsulatedContentInfo,
		 *       authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
		 *       mac MessageAuthenticationCode,
		 *       unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
		 *
		 * AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
		 *
		 * UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
		 *
		 * MessageAuthenticationCode ::= OCTET STRING
		 * </pre>
		 */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(9);
            v.Add(m_version);
            v.AddOptionalTagged(false, 0, m_originatorInfo);
            v.Add(m_recipientInfos, m_macAlgorithm);
            v.AddOptionalTagged(false, 1, m_digestAlgorithm);
            v.Add(m_encapsulatedContentInfo);
            v.AddOptionalTagged(false, 2, m_authAttrs);
            v.Add(m_mac);
            v.AddOptionalTagged(false, 3, m_unauthAttrs);
            return new BerSequence(v);
        }

        public static int CalculateVersion(OriginatorInfo origInfo) => CalculateVersionField(origInfo).IntValueExact;

        private static DerInteger CalculateVersionField(OriginatorInfo originatorInfo)
		{
            /*
             * IF (originatorInfo is present) AND
             *    ((any certificates with a type of other are present) OR
             *    (any crls with a type of other are present))
             * THEN version is 3
             * ELSE
             *    IF ((originatorInfo is present) AND
             *       (any version 2 attribute certificates are present))
             *    THEN version is 1
             *    ELSE version is 0
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
                                return DerInteger.Three;
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
                                return DerInteger.Three;

                            // CertificateChoices.v2AttrCert
                            anyV2AttrCerts = anyV2AttrCerts || tagged.HasContextTag(2);
                        }
                    }

                    if (anyV2AttrCerts)
                        return DerInteger.One;
                }
            }
            return DerInteger.Zero;
		}
	}
}
