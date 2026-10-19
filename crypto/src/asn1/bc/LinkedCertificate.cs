using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.BC
{
    /// <summary>Extension to tie an alternate certificate to the containing certificate.</summary>
    /// <remarks>
    /// <code>
    /// LinkedCertificate := SEQUENCE {
    ///     digest          DigestInfo,                   -- digest of PQC certificate
    ///     certLocation    GeneralName,                  -- location of PQC certificate
    ///     certIssuer      [0] Name OPTIONAL,            -- issuer of PQC cert(if different from current certificate)
    ///     cACerts         [1] GeneralNames OPTIONAL,    -- CA certificates for PQC cert(one of more locations)
    /// }
    /// </code>
    /// </remarks>
    // TODO[api] Make sealed
    public class LinkedCertificate
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="LinkedCertificate"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="LinkedCertificate"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="LinkedCertificate"/>, or null if <paramref name="obj"/> is null.</returns>
        public static LinkedCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is LinkedCertificate linkedCertificate)
                return linkedCertificate;
            return new LinkedCertificate(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="LinkedCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="LinkedCertificate"/>.</returns>
        public static LinkedCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LinkedCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="LinkedCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="LinkedCertificate"/>.</returns>
        public static LinkedCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LinkedCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DigestInfo m_digest;
        private readonly GeneralName m_certLocation;
        private readonly X509Name m_certIssuer;
        private readonly GeneralNames m_cACerts;

        /// <summary>Create a new <see cref="LinkedCertificate"/>.</summary>
        /// <param name="digest">The digest.</param>
        /// <param name="certLocation">The cert location.</param>
        public LinkedCertificate(DigestInfo digest, GeneralName certLocation)
            : this(digest, certLocation, null, null)
        {
        }

        /// <summary>Create a new <see cref="LinkedCertificate"/>.</summary>
        /// <param name="digest">The digest.</param>
        /// <param name="certLocation">The cert location.</param>
        /// <param name="certIssuer">The cert issuer.</param>
        /// <param name="caCerts">The ca certs.</param>
        public LinkedCertificate(DigestInfo digest, GeneralName certLocation, X509Name certIssuer, GeneralNames caCerts)
        {
            m_digest = digest ?? throw new ArgumentNullException(nameof(digest));
            m_certLocation = certLocation ?? throw new ArgumentNullException(nameof(certLocation));
            m_certIssuer = certIssuer;
            m_cACerts = caCerts;
        }

        private LinkedCertificate(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digest = Asn1Utilities.Read(seq, ref pos, DigestInfo.GetInstance);
            m_certLocation = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);
            m_certIssuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, X509Name.GetTagged); // CHOICE
            m_cACerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, GeneralNames.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public virtual DigestInfo Digest => m_digest;

        /// <summary>Gets the cert location.</summary>
        public virtual GeneralName CertLocation => m_certLocation;

        /// <summary>Gets the cert issuer.</summary>
        public virtual X509Name CertIssuer => m_certIssuer;

        /// <summary>Gets the CA certs.</summary>
        public virtual GeneralNames CACerts => m_cACerts;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_digest, m_certLocation);
            v.AddOptionalTagged(true, 0, m_certIssuer); // CHOICE
            v.AddOptionalTagged(false, 1, m_cACerts);
            return new DerSequence(v);
        }
    }
}
