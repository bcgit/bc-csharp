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

        public static AuthenticatedData GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new AuthenticatedData(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private DerInteger version;
		private OriginatorInfo originatorInfo;
		private Asn1Set recipientInfos;
		private AlgorithmIdentifier macAlgorithm;
		private AlgorithmIdentifier digestAlgorithm;
		private ContentInfo encapsulatedContentInfo;
		private Asn1Set authAttrs;
		private Asn1OctetString mac;
		private Asn1Set unauthAttrs;

		public AuthenticatedData(
			OriginatorInfo		originatorInfo,
			Asn1Set				recipientInfos,
			AlgorithmIdentifier	macAlgorithm,
			AlgorithmIdentifier	digestAlgorithm,
			ContentInfo			encapsulatedContent,
			Asn1Set				authAttrs,
			Asn1OctetString		mac,
			Asn1Set				unauthAttrs)
		{
			if (digestAlgorithm != null || authAttrs != null)
			{
				if (digestAlgorithm == null || authAttrs == null)
				{
					throw new ArgumentException("digestAlgorithm and authAttrs must be set together");
				}
			}

			version = new DerInteger(CalculateVersion(originatorInfo));

			this.originatorInfo = originatorInfo;
			this.macAlgorithm = macAlgorithm;
			this.digestAlgorithm = digestAlgorithm;
			this.recipientInfos = recipientInfos;
			this.encapsulatedContentInfo = encapsulatedContent;
			this.authAttrs = authAttrs;
			this.mac = mac;
			this.unauthAttrs = unauthAttrs;
		}

		private AuthenticatedData(Asn1Sequence seq)
		{
			int index = 0;

			version = (DerInteger)seq[index++];

			Asn1Encodable tmp = seq[index++];
			if (tmp is Asn1TaggedObject taggedObject1)
			{
				originatorInfo = OriginatorInfo.GetInstance(taggedObject1, false);
				tmp = seq[index++];
			}

			recipientInfos = Asn1Set.GetInstance(tmp);
			macAlgorithm = AlgorithmIdentifier.GetInstance(seq[index++]);

			tmp = seq[index++];
			if (tmp is Asn1TaggedObject taggedObject2)
			{
				digestAlgorithm = AlgorithmIdentifier.GetInstance(taggedObject2, false);
				tmp = seq[index++];
			}

			encapsulatedContentInfo = ContentInfo.GetInstance(tmp);

			tmp = seq[index++];
			if (tmp is Asn1TaggedObject taggedObject3)
			{
				authAttrs = Asn1Set.GetInstance(taggedObject3, false);
				tmp = seq[index++];
			}

			mac = Asn1OctetString.GetInstance(tmp);

			if (seq.Count > index)
			{
				unauthAttrs = Asn1Set.GetInstance((Asn1TaggedObject)seq[index], false);
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

		public AlgorithmIdentifier MacAlgorithm
		{
			get { return macAlgorithm; }
		}

        public AlgorithmIdentifier DigestAlgorithm
        {
            get { return digestAlgorithm; }
        }

		public ContentInfo EncapsulatedContentInfo
		{
			get { return encapsulatedContentInfo; }
		}

		public Asn1Set AuthAttrs
		{
			get { return authAttrs; }
		}

		public Asn1OctetString Mac
		{
			get { return mac; }
		}

		public Asn1Set UnauthAttrs
		{
			get { return unauthAttrs; }
		}

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
			Asn1EncodableVector v = new Asn1EncodableVector(version);
            v.AddOptionalTagged(false, 0, originatorInfo);
			v.Add(recipientInfos, macAlgorithm);
            v.AddOptionalTagged(false, 1, digestAlgorithm);
			v.Add(encapsulatedContentInfo);
            v.AddOptionalTagged(false, 2, authAttrs);
			v.Add(mac);
            v.AddOptionalTagged(false, 3, unauthAttrs);
			return new BerSequence(v);
		}

		public static int CalculateVersion(OriginatorInfo origInfo)
		{
			if (origInfo == null)
				return 0;

			int ver = 0;

			foreach (object obj in origInfo.Certificates)
			{
				if (obj is Asn1TaggedObject tag)
				{
					if (tag.TagNo == 2)
					{
						ver = 1;
					}
					else if (tag.TagNo == 3)
					{
						ver = 3;
						break;
					}
				}
			}

			foreach (object obj in origInfo.Crls)
			{
				if (obj is Asn1TaggedObject tag)
				{
					if (tag.TagNo == 1)
					{
						ver = 3;
						break;
					}
				}
			}

			return ver;
		}
	}
}
