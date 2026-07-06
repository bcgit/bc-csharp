using System;

using Org.BouncyCastle.Asn1.Cms;

namespace Org.BouncyCastle.Asn1.Microsoft
{
    /// <summary>
    /// The Microsoft Authenticode time stamp request, as sent to a legacy (pre-RFC 3161) Authenticode time stamping
    /// service (the protocol behind <c>signtool /t</c>; the RFC 3161 protocol is <c>signtool /tr</c>).
    /// </summary>
    /// <remarks>
    /// <code>
    /// TimeStampRequest ::= SEQUENCE {
    ///     countersignatureType OBJECT IDENTIFIER,
    ///     attributes Attributes OPTIONAL,
    ///     content ContentInfo
    /// }
    /// </code>
    /// <para>
    /// The countersignatureType identifying a time stamp countersignature is the exact OID 1.3.6.1.4.1.311.3.2.1
    /// (<see cref="MicrosoftObjectIdentifiers.MicrosoftTimeStampRequest"/>).
    /// No attributes are currently included in requests.The content is a PKCS#7 ContentInfo of type data whose content
    /// is the encryptedDigest(signature) from the SignerInfo of the PKCS#7 SignedData to be time stamped.
    /// </para>
    /// <para>
    /// On the wire the request travels as the body of an HTTP 1.1 POST, base64 encoded, with Content - Type
    /// application/octet-stream. The response is a base64 encoded PKCS#7 SignedData whose SignerInfo the requester
    /// copies into the original SignedData as a PKCS#9 countersignature (an unsigned attribute of the original
    /// SignerInfo), merging the time stamper's certificates into the original SignedData's certificate set.
    /// </para>
    /// </remarks>
    /// <seealso href="https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures">
    /// Time Stamping Authenticode Signatures
    /// </seealso>
    public class TimeStampRequest
        : Asn1Encodable
    {
        private readonly DerObjectIdentifier m_countersignatureType;
        private readonly Attributes m_attributes;
        private readonly ContentInfo m_content;

        public static TimeStampRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TimeStampRequest timeStampRequest)
                return timeStampRequest;
            return new TimeStampRequest(Asn1Sequence.GetInstance(obj));
        }

        public static TimeStampRequest GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampRequest(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static TimeStampRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TimeStampRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private TimeStampRequest(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_countersignatureType = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_attributes = Asn1Utilities.ReadOptional(seq, ref pos, Attributes.GetOptional);
            m_content = Asn1Utilities.Read(seq, ref pos, ContentInfo.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>
        /// Construct a time stamp request for the given content using the standard Authenticode countersignature type
        /// OID, 1.3.6.1.4.1.311.3.2.1, and no attributes.
        /// </summary>
        /// <param name="content">A ContentInfo of type data carrying the signature to be time stamped.</param>
        public TimeStampRequest(ContentInfo content)
            : this(MicrosoftObjectIdentifiers.MicrosoftTimeStampRequest, attributes: null, content)
        {
        }

        public TimeStampRequest(DerObjectIdentifier countersignatureType, Attributes attributes, ContentInfo content)
        {
            m_countersignatureType = countersignatureType ?? throw new ArgumentNullException(nameof(countersignatureType));
            m_attributes = attributes;
            m_content = content ?? throw new ArgumentNullException(nameof(content));
        }

        public DerObjectIdentifier CountersignatureType => m_countersignatureType;

        public Attributes Attributes => m_attributes;

        public ContentInfo Content => m_content;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_countersignatureType);
            v.AddOptional(m_attributes);
            v.Add(m_content);
            return new DerSequence(v);
        }
    }
}
