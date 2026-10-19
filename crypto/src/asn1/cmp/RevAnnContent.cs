using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The RevAnnContent structure of RFC 4210, the body of a revocation announcement.</summary>
    public class RevAnnContent
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RevAnnContent"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RevAnnContent"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RevAnnContent"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RevAnnContent GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevAnnContent revAnnContent)
                return revAnnContent;
            return new RevAnnContent(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RevAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevAnnContent"/>.</returns>
        public static RevAnnContent GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevAnnContent(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="RevAnnContent"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevAnnContent"/>.</returns>
        public static RevAnnContent GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevAnnContent(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly PkiStatusEncodable m_status;
        private readonly CertId m_certID;
        private readonly Asn1GeneralizedTime m_willBeRevokedAt;
        private readonly Asn1GeneralizedTime m_badSinceDate;
        private readonly X509Extensions m_crlDetails;

        /// <summary>Create a new <see cref="RevAnnContent"/>.</summary>
        /// <param name="status">The status.</param>
        /// <param name="certID">The cert ID.</param>
        /// <param name="willBeRevokedAt">The will be revoked at.</param>
        /// <param name="badSinceDate">The bad since date.</param>
        public RevAnnContent(PkiStatusEncodable status, CertId certID, Asn1GeneralizedTime willBeRevokedAt,
            Asn1GeneralizedTime badSinceDate)
            : this(status, certID, willBeRevokedAt, badSinceDate, null)
        {
        }

        /// <summary>Create a new <see cref="RevAnnContent"/>.</summary>
        /// <param name="status">The status.</param>
        /// <param name="certID">The cert ID.</param>
        /// <param name="willBeRevokedAt">The will be revoked at.</param>
        /// <param name="badSinceDate">The bad since date.</param>
        /// <param name="crlDetails">The crl details.</param>
        public RevAnnContent(PkiStatusEncodable status, CertId certID, Asn1GeneralizedTime willBeRevokedAt,
            Asn1GeneralizedTime badSinceDate, X509Extensions crlDetails)
        {
            m_status = status ?? throw new ArgumentNullException(nameof(status));
            m_certID = certID ?? throw new ArgumentNullException(nameof(certID));
            m_willBeRevokedAt = willBeRevokedAt ?? throw new ArgumentNullException(nameof(willBeRevokedAt));
            m_badSinceDate = badSinceDate ?? throw new ArgumentNullException(nameof(badSinceDate));
            m_crlDetails = crlDetails;
        }

        private RevAnnContent(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 4 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_status = Asn1Utilities.Read(seq, ref pos, PkiStatusEncodable.GetInstance);
            m_certID = Asn1Utilities.Read(seq, ref pos, CertId.GetInstance);
            m_willBeRevokedAt = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);
            m_badSinceDate = Asn1Utilities.Read(seq, ref pos, Asn1GeneralizedTime.GetInstance);
            m_crlDetails = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the status.</summary>
        public virtual PkiStatusEncodable Status => m_status;

        /// <summary>Gets the cert ID.</summary>
        public virtual CertId CertID => m_certID;

        /// <summary>Gets the will be revoked at.</summary>
        public virtual Asn1GeneralizedTime WillBeRevokedAt => m_willBeRevokedAt;

        /// <summary>Gets the bad since date.</summary>
        public virtual Asn1GeneralizedTime BadSinceDate => m_badSinceDate;

        /// <summary>Gets the crl details.</summary>
        public virtual X509Extensions CrlDetails => m_crlDetails;

        /**
         * <pre>
         * RevAnnContent ::= SEQUENCE {
         *       status              PKIStatus,
         *       certId              CertId,
         *       willBeRevokedAt     GeneralizedTime,
         *       badSinceDate        GeneralizedTime,
         *       crlDetails          Extensions  OPTIONAL
         *        -- extra CRL details (e.g., crl number, reason, location, etc.)
         * }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_status, m_certID, m_willBeRevokedAt, m_badSinceDate);
            v.AddOptional(m_crlDetails);
            return new DerSequence(v);
        }
    }
}
