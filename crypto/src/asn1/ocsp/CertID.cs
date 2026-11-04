using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The CertID structure of RFC 6960, identifying a certificate in an OCSP request or response.</summary>
    public class CertID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertID"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertID"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertID"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertID GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertID certID)
                return certID;
            return new CertID(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertID"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertID"/>.</returns>
        public static CertID GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new CertID(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="CertID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertID"/>.</returns>
        public static CertID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_issuerNameHash;
        private readonly Asn1OctetString m_issuerKeyHash;
        private readonly DerInteger m_serialNumber;

        /// <summary>Create a new <see cref="CertID"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="issuerNameHash">The issuer name hash.</param>
        /// <param name="issuerKeyHash">The issuer key hash.</param>
        /// <param name="serialNumber">The serial number.</param>
        public CertID(AlgorithmIdentifier hashAlgorithm, Asn1OctetString issuerNameHash, Asn1OctetString issuerKeyHash,
            DerInteger serialNumber)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_issuerNameHash = issuerNameHash ?? throw new ArgumentNullException(nameof(issuerNameHash));
            m_issuerKeyHash = issuerKeyHash ?? throw new ArgumentNullException(nameof(issuerKeyHash));
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        }

        private CertID(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_issuerNameHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_issuerKeyHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_serialNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the issuer name hash.</summary>
        public Asn1OctetString IssuerNameHash => m_issuerNameHash;

        /// <summary>Gets the issuer key hash.</summary>
        public Asn1OctetString IssuerKeyHash => m_issuerKeyHash;

        /// <summary>Gets the serial number.</summary>
        public DerInteger SerialNumber => m_serialNumber;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * CertID          ::=     Sequence {
         *     hashAlgorithm       AlgorithmIdentifier,
         *     issuerNameHash      OCTET STRING, -- Hash of Issuer's DN
         *     issuerKeyHash       OCTET STRING, -- Hash of Issuers public key
         *     serialNumber        CertificateSerialNumber }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() =>
            new DerSequence(m_hashAlgorithm, m_issuerNameHash, m_issuerKeyHash, m_serialNumber);
    }
}
