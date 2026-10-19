using System;
using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>
    /// An entry of a CRL: a revoked certificate's serial number, the revocation date and the entry extensions.
    /// </summary>
    public class CrlEntry
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlEntry"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CrlEntry"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CrlEntry"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlEntry GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlEntry crlEntry)
                return crlEntry;
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlEntry(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CrlEntry"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlEntry"/>.</returns>
        public static CrlEntry GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlEntry(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="CrlEntry"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlEntry"/>.</returns>
        public static CrlEntry GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new CrlEntry(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Sequence m_seq;

        private readonly DerInteger m_userCertificate;
        private readonly Time m_revocationDate;
        private readonly X509Extensions m_crlEntryExtensions;

        /// <summary>Create a new <see cref="CrlEntry"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public CrlEntry(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_userCertificate = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_revocationDate = Asn1Utilities.Read(seq, ref pos, Time.GetInstance);
            m_crlEntryExtensions = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_seq = seq;
        }

        /// <summary>Gets the user certificate.</summary>
        public DerInteger UserCertificate => m_userCertificate;

        /// <summary>Gets the revocation date.</summary>
        public Time RevocationDate => m_revocationDate;

        public X509Extensions Extensions => m_crlEntryExtensions;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_seq;
    }

    /**
     * PKIX RFC-2459 - TbsCertList object.
     * <pre>
     * TbsCertList  ::=  Sequence  {
     *      version                 Version OPTIONAL,
     *                                   -- if present, shall be v2
     *      signature               AlgorithmIdentifier,
     *      issuer                  Name,
     *      thisUpdate              Time,
     *      nextUpdate              Time OPTIONAL,
     *      revokedCertificates     Sequence OF Sequence  {
     *           userCertificate         CertificateSerialNumber,
     *           revocationDate          Time,
     *           crlEntryExtensions      Extensions OPTIONAL
     *                                         -- if present, shall be v2
     *                                }  OPTIONAL,
     *      crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
     *                                         -- if present, shall be v2
     *                                }
     * </pre>
     */
    public class TbsCertificateList
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="TbsCertificateList"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="TbsCertificateList"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="TbsCertificateList"/>, or null if <paramref name="obj"/> is null.</returns>
        public static TbsCertificateList GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TbsCertificateList tbsCertificateList)
                return tbsCertificateList;
            return new TbsCertificateList(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="TbsCertificateList"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TbsCertificateList"/>.</returns>
        public static TbsCertificateList GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new TbsCertificateList(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="TbsCertificateList"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="TbsCertificateList"/>.</returns>
        public static TbsCertificateList GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TbsCertificateList(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_seq;

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_signature;
        private readonly X509Name m_issuer;
        private readonly Time m_thisUpdate;
        private readonly Time m_nextUpdate;
        private readonly Asn1Sequence m_revokedCertificates;
        private readonly X509Extensions m_crlExtensions;

        private TbsCertificateList(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 7)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // TODO[api] This field is not actually declared with a DEFAULT
            m_version = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional) ?? DerInteger.Zero;
            m_signature = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_issuer = Asn1Utilities.Read(seq, ref pos, X509Name.GetInstance);
            m_thisUpdate = Asn1Utilities.Read(seq, ref pos, Time.GetInstance);
            m_nextUpdate = Asn1Utilities.ReadOptional(seq, ref pos, Time.GetOptional);
            m_revokedCertificates = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);
            m_crlExtensions = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, X509Extensions.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            // RFC 5280 sec. 5.1.2.3: the CRL issuer field MUST contain a non-empty distinguished name.
            if (m_issuer.IsEmpty)
                throw new ArgumentException("CRL issuer is an empty distinguished name");

            m_seq = seq;
        }

        /// <summary>Gets the version.</summary>
        public int Version => m_version.IntValueExact + 1;

        /// <summary>Gets the version number.</summary>
        public DerInteger VersionNumber => m_version;

        /// <summary>Gets the signature.</summary>
        public AlgorithmIdentifier Signature => m_signature;

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_issuer;

        /// <summary>Gets the this update.</summary>
        public Time ThisUpdate => m_thisUpdate;

        /// <summary>Gets the next update.</summary>
        public Time NextUpdate => m_nextUpdate;

        /// <summary>Return the revoked certificates.</summary>
        // TODO[api] Don't convert null to empty array
        public CrlEntry[] GetRevokedCertificates() =>
            m_revokedCertificates?.MapElements(CrlEntry.GetInstance) ?? Array.Empty<CrlEntry>();

        /// <summary>Return the revoked certificate enumeration.</summary>
        public IEnumerable<CrlEntry> GetRevokedCertificateEnumeration() =>
            CollectionUtilities.Select(m_revokedCertificates ?? DerSequence.Empty, CrlEntry.GetInstance);

        public X509Extensions Extensions => m_crlExtensions;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_seq;
    }
}
