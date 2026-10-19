using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cms
{
    /// <summary>The AuthenticatedData structure of RFC 5652.</summary>
    public class AuthenticatedData
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AuthenticatedData"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AuthenticatedData"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AuthenticatedData"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AuthenticatedData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthenticatedData authenticatedData)
                return authenticatedData;
            return new AuthenticatedData(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AuthenticatedData"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AuthenticatedData"/>.</returns>
        public static AuthenticatedData GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new AuthenticatedData(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="AuthenticatedData"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AuthenticatedData"/>.</returns>
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

        /// <summary>Create a new <see cref="AuthenticatedData"/>.</summary>
        /// <param name="originatorInfo">The originator info.</param>
        /// <param name="recipientInfos">The recipient infos.</param>
        /// <param name="macAlgorithm">The mac algorithm.</param>
        /// <param name="digestAlgorithm">The digest algorithm.</param>
        /// <param name="encapsulatedContent">The encapsulated content.</param>
        /// <param name="authAttrs">The auth attrs.</param>
        /// <param name="mac">The MAC.</param>
        /// <param name="unauthAttrs">The unauth attrs.</param>
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

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_originatorInfo = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, OriginatorInfo.GetTagged);
            m_recipientInfos = Asn1Utilities.Read(seq, ref pos, Asn1Set.GetInstance);
            m_macAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_digestAlgorithm = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, AlgorithmIdentifier.GetTagged);
            m_encapsulatedContentInfo = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);
            m_authAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, Asn1Set.GetTagged);
            m_mac = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_unauthAttrs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, false, Asn1Set.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        public OriginatorInfo OriginatorInfo => m_originatorInfo;

        /// <summary>Gets the recipient infos.</summary>
        public Asn1Set RecipientInfos => m_recipientInfos;

        /// <summary>Gets the mac algorithm.</summary>
        public AlgorithmIdentifier MacAlgorithm => m_macAlgorithm;

        /// <summary>Gets the digest algorithm.</summary>
        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        /// <summary>Gets the encapsulated content info.</summary>
        public ContentInfo EncapsulatedContentInfo => m_encapsulatedContentInfo;

        /// <summary>Gets the auth attrs.</summary>
        public Asn1Set AuthAttrs => m_authAttrs;

        /// <summary>Gets the mac.</summary>
        public Asn1OctetString Mac => m_mac;

        /// <summary>Gets the unauth attrs.</summary>
        public Asn1Set UnauthAttrs => m_unauthAttrs;

        /// <summary>Produce an object suitable for an <see cref="Asn1OutputStream"/>.</summary>
        /// <remarks>
        /// <code>
        /// AuthenticatedData::= SEQUENCE {
        ///     version CMSVersion,
        ///     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
        ///     recipientInfos RecipientInfos,
        ///     macAlgorithm MessageAuthenticationCodeAlgorithm,
        ///     digestAlgorithm[1] DigestAlgorithmIdentifier OPTIONAL,
        ///     encapContentInfo EncapsulatedContentInfo,
        ///     authAttrs[2] IMPLICIT AuthAttributes OPTIONAL,
        ///     mac MessageAuthenticationCode,
        ///     unauthAttrs[3] IMPLICIT UnauthAttributes OPTIONAL }
        ///
        /// AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
        ///
        /// UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
        ///
        /// MessageAuthenticationCode ::= OCTET STRING
        /// </code>
        /// </remarks>
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

            int contents = OriginatorInfoContents.Classify(originatorInfo);
            switch (contents)
            {
            case OriginatorInfoContents.Other:
                return DerInteger.Three;
            case OriginatorInfoContents.V2AttributeCertificate:
                return DerInteger.One;
            default:
                return DerInteger.Zero;
            }
        }
    }
}
