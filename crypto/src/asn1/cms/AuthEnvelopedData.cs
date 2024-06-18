using System;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class AuthEnvelopedData
		: Asn1Encodable
	{
        public static AuthEnvelopedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthEnvelopedData authEnvelopedData)
                return authEnvelopedData;
            return new AuthEnvelopedData(Asn1Sequence.GetInstance(obj));
        }

        public static AuthEnvelopedData GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new AuthEnvelopedData(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly DerInteger m_version;
        private readonly OriginatorInfo m_originatorInfo;
        private readonly Asn1Set m_recipientInfos;
        private readonly EncryptedContentInfo m_authEncryptedContentInfo;
        private readonly Asn1Set m_authAttrs;
        private readonly Asn1OctetString m_mac;
        private readonly Asn1Set m_unauthAttrs;

        public AuthEnvelopedData(OriginatorInfo originatorInfo, Asn1Set recipientInfos,
			EncryptedContentInfo authEncryptedContentInfo, Asn1Set authAttrs, Asn1OctetString mac,
			Asn1Set unauthAttrs)
        {
            m_version = DerInteger.Zero;
			m_originatorInfo = originatorInfo;
			m_recipientInfos = recipientInfos ?? throw new ArgumentNullException(nameof(recipientInfos));
			m_authEncryptedContentInfo = authEncryptedContentInfo ?? throw new ArgumentNullException(nameof(authEncryptedContentInfo));
            m_authAttrs = authAttrs;
			m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
			m_unauthAttrs = unauthAttrs;

            Validate();
        }

        private AuthEnvelopedData(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_originatorInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, OriginatorInfo.GetInstance);
            m_recipientInfos = Asn1Set.GetInstance(seq[pos++]);
            m_authEncryptedContentInfo = EncryptedContentInfo.GetInstance(seq[pos++]);
            m_authAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, Asn1Set.GetInstance);
            m_mac = Asn1OctetString.GetInstance(seq[pos++]);
            m_unauthAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, Asn1Set.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            Validate();
		}

        private void Validate()
        {
            // "It MUST be set to 0."
            if (!m_version.HasValue(0))
                throw new ArgumentException("AuthEnvelopedData version number must be 0");

            // "There MUST be at least one element in the collection."
            if (m_recipientInfos.Count < 1)
                throw new ArgumentException("AuthEnvelopedData requires at least 1 RecipientInfo");

            // "The authAttrs MUST be present if the content type carried in EncryptedContentInfo is not id-data."
            if (!CmsObjectIdentifiers.Data.Equals(m_authEncryptedContentInfo.ContentType))
            {
                if (m_authAttrs == null || m_authAttrs.Count < 1)
                    throw new ArgumentException("authAttrs must be present with non-data content");
            }
        }

        public DerInteger Version => m_version;

		public OriginatorInfo OriginatorInfo => m_originatorInfo;

		public Asn1Set RecipientInfos => m_recipientInfos;

		public EncryptedContentInfo AuthEncryptedContentInfo => m_authEncryptedContentInfo;

		public Asn1Set AuthAttrs => m_authAttrs;

		public Asn1OctetString Mac => m_mac;

		public Asn1Set UnauthAttrs => m_unauthAttrs;

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 * <pre>
		 * AuthEnvelopedData ::= SEQUENCE {
		 *   version CMSVersion,
		 *   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
		 *   recipientInfos RecipientInfos,
		 *   authEncryptedContentInfo EncryptedContentInfo,
		 *   authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
		 *   mac MessageAuthenticationCode,
		 *   unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
		 * </pre>
		 */
	    public override Asn1Object ToAsn1Object()
		{
			Asn1EncodableVector v = new Asn1EncodableVector(7);
			v.Add(m_version);
            v.AddOptionalTagged(false, 0, m_originatorInfo);
			v.Add(m_recipientInfos, m_authEncryptedContentInfo);

			// "authAttrs optionally contains the authenticated attributes."
            // "AuthAttributes MUST be DER encoded, even if the rest of the
            // AuthEnvelopedData structure is BER encoded."
            v.AddOptionalTagged(false, 1, m_authAttrs);

            v.Add(m_mac);

            // "unauthAttrs optionally contains the unauthenticated attributes."
            v.AddOptionalTagged(false, 2, m_unauthAttrs);

            return new BerSequence(v);
		}
	}
}
