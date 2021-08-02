using System;

namespace Org.BouncyCastle.Asn1.Cms
{
	/**
	 * Produce an object suitable for an Asn1OutputStream.
	 * 
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
	public class AuthEnvelopedDataParser
	{
		private Asn1SequenceParser	seq;
		private DerInteger			version;
		private IAsn1Convertible	nextObject;
		private bool				originatorInfoCalled;
        private bool                isData;

		public AuthEnvelopedDataParser(
			Asn1SequenceParser	seq)
		{
			this.seq = seq;

			// "It MUST be set to 0."
			this.version = (DerInteger)seq.ReadObject();
			if (!version.HasValue(0))
				throw new Asn1ParsingException("AuthEnvelopedData version number must be 0");
		}

		public DerInteger Version
		{
			get { return version; }
		}

		public OriginatorInfo GetOriginatorInfo()
		{
			originatorInfoCalled = true;

			if (nextObject == null)
			{
				nextObject = seq.ReadObject();
			}

			if (nextObject is Asn1TaggedObjectParser && ((Asn1TaggedObjectParser)nextObject).TagNo == 0)
			{
				Asn1SequenceParser originatorInfo = (Asn1SequenceParser) ((Asn1TaggedObjectParser)nextObject).GetObjectParser(Asn1Tags.Sequence, false);
				nextObject = null;
				return OriginatorInfo.GetInstance(originatorInfo.ToAsn1Object());
			}

			return null;
		}

		public Asn1SetParser GetRecipientInfos()
		{
			if (!originatorInfoCalled)
			{
				GetOriginatorInfo();
			}

			if (nextObject == null)
			{
				nextObject = seq.ReadObject();
			}

			Asn1SetParser recipientInfos = (Asn1SetParser)nextObject;
			nextObject = null;
			return recipientInfos;
		}

		public EncryptedContentInfoParser GetAuthEncryptedContentInfo() 
		{
			if (nextObject == null)
			{
				nextObject = seq.ReadObject();
			}

			if (nextObject != null)
			{
				Asn1SequenceParser o = (Asn1SequenceParser) nextObject;
				nextObject = null;
                EncryptedContentInfoParser encryptedContentInfoParser = new EncryptedContentInfoParser(o);
                isData = CmsObjectIdentifiers.Data.Equals(encryptedContentInfoParser.ContentType);
                return encryptedContentInfoParser;
			}

			return null;
		}
		
		public Asn1SetParser GetAuthAttrs()
		{
			if (nextObject == null)
			{
				nextObject = seq.ReadObject();
			}

			if (nextObject is Asn1TaggedObjectParser)
			{
				IAsn1Convertible o = nextObject;
				nextObject = null;
				return (Asn1SetParser)((Asn1TaggedObjectParser)o).GetObjectParser(Asn1Tags.Set, false);
			}

			// "The authAttrs MUST be present if the content type carried in
			// EncryptedContentInfo is not id-data."
			if (!isData)
				throw new Asn1ParsingException("authAttrs must be present with non-data content");

			return null;
		}
		
		public Asn1OctetString GetMac()
		{
			if (nextObject == null)
			{
				nextObject = seq.ReadObject();
			}

			IAsn1Convertible o = nextObject;
			nextObject = null;

			return Asn1OctetString.GetInstance(o.ToAsn1Object());
		}
		
		public Asn1SetParser GetUnauthAttrs()
		{
			if (nextObject == null)
			{
				nextObject = seq.ReadObject();
			}

			if (nextObject != null)
			{
				IAsn1Convertible o = nextObject;
				nextObject = null;
				return (Asn1SetParser)((Asn1TaggedObjectParser)o).GetObjectParser(Asn1Tags.Set, false);
			}

			return null;
		}
	}
}
