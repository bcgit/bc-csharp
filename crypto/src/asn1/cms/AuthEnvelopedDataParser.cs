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
        private Asn1SequenceParser seq;
        private DerInteger version;
        private IAsn1Convertible nextObject;
        private bool originatorInfoCalled;
        private bool                isData;

        /// <summary>Create a new <see cref="AuthEnvelopedDataParser"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        public AuthEnvelopedDataParser(
            Asn1SequenceParser seq)
        {
            this.seq = seq;

            // "It MUST be set to 0."
            this.version = (DerInteger)seq.ReadObject();
            if (!version.HasValue(0))
                throw new Asn1ParsingException("AuthEnvelopedData version number must be 0");
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version
        {
            get { return version; }
        }

        /// <summary>Return the originator info.</summary>
        public OriginatorInfo GetOriginatorInfo()
        {
            originatorInfoCalled = true;

            if (nextObject == null)
            {
                nextObject = seq.ReadObject();
            }

            if (nextObject is Asn1TaggedObjectParser o)
            {
                if (o.HasContextTag(0))
                {
                    Asn1SequenceParser originatorInfo = (Asn1SequenceParser)o.ParseBaseUniversal(false, Asn1Tags.Sequence);
                    nextObject = null;
                    return OriginatorInfo.GetInstance(originatorInfo.ToAsn1Object());
                }
            }

            return null;
        }

        /// <summary>Return the recipient infos.</summary>
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

        /// <summary>Return the auth encrypted content info.</summary>
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

        /// <summary>Return the auth attrs.</summary>
        public Asn1SetParser GetAuthAttrs()
        {
            if (nextObject == null)
            {
                nextObject = seq.ReadObject();
            }

            if (nextObject is Asn1TaggedObjectParser o)
            {
                nextObject = null;
                return (Asn1SetParser)Asn1Utilities.ParseContextBaseUniversal(o, 1, false, Asn1Tags.SetOf);
            }

            // "The authAttrs MUST be present if the content type carried in EncryptedContentInfo is not id-data."
            if (!isData)
                throw new Asn1ParsingException("authAttrs must be present with non-data content");

            return null;
        }

        /// <summary>Return the mac.</summary>
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

        /// <summary>Return the unauth attrs.</summary>
        public Asn1SetParser GetUnauthAttrs()
        {
            if (nextObject == null)
            {
                nextObject = seq.ReadObject();
            }

            if (nextObject != null)
            {
                Asn1TaggedObjectParser o = (Asn1TaggedObjectParser)nextObject;
                nextObject = null;
                return (Asn1SetParser)Asn1Utilities.ParseContextBaseUniversal(o, 2, false, Asn1Tags.SetOf);
            }

            return null;
        }
    }
}
