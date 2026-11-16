using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /// <summary>The CertId structure of RFC 4211: an issuer and a serial number.</summary>
    public class CertId
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertId"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertId"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertId"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertId GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertId certId)
                return certId;
            return new CertId(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertId"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertId"/>.</returns>
        public static CertId GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new CertId(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="CertId"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertId"/>.</returns>
        public static CertId GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertId(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralName m_issuer;
        private readonly DerInteger m_serialNumber;

        private CertId(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_issuer = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);
            m_serialNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CertId"/>.</summary>
        /// <param name="issuer">The issuer.</param>
        /// <param name="serialNumber">The serial number.</param>
        public CertId(GeneralName issuer, DerInteger serialNumber)
        {
            m_issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
            m_serialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        }

        /// <summary>Gets the issuer.</summary>
        public virtual GeneralName Issuer => m_issuer;

        /// <summary>Gets the serial number.</summary>
        public virtual DerInteger SerialNumber => m_serialNumber;

        /**
         * <pre>
         * CertId ::= SEQUENCE {
         *                 issuer           GeneralName,
         *                 serialNumber     INTEGER }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_issuer, m_serialNumber);
    }
}
