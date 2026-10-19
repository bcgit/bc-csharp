using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * PKIX RFC-2459
     *
     * The X.509 v2 CRL syntax is as follows.  For signature calculation,
     * the data that is to be signed is ASN.1 Der encoded.
     *
     * <pre>
     * CertificateList  ::=  Sequence  {
     *      tbsCertList          TbsCertList,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     * </pre>
     */
    public class CertificateList
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertificateList"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertificateList"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertificateList"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertificateList GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificateList certificateList)
                return certificateList;
            return new CertificateList(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertificateList"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificateList"/>.</returns>
        public static CertificateList GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new CertificateList(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="CertificateList"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="CertificateList"/>, or null if <paramref name="element"/> is null.</returns>
        public static CertificateList GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is CertificateList certificateList)
                return certificateList;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new CertificateList(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="CertificateList"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificateList"/>.</returns>
        public static CertificateList GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificateList(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly TbsCertificateList m_tbsCertList;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signatureValue;

        private CertificateList(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_tbsCertList = Asn1Utilities.Read(seq, ref pos, TbsCertificateList.GetInstance);
            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signatureValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the tbs cert list.</summary>
        public TbsCertificateList TbsCertList => m_tbsCertList;

        /// <summary>Return the revoked certificates.</summary>
        public CrlEntry[] GetRevokedCertificates() => m_tbsCertList.GetRevokedCertificates();

        /// <summary>Return the revoked certificate enumeration.</summary>
        public IEnumerable<CrlEntry> GetRevokedCertificateEnumeration() =>
            m_tbsCertList.GetRevokedCertificateEnumeration();

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        /// <summary>Gets the signature.</summary>
        public DerBitString Signature => m_signatureValue;

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignatureOctets() => m_signatureValue.GetOctets();

        /// <summary>Gets the version.</summary>
        public int Version => m_tbsCertList.Version;

        /// <summary>Gets the issuer.</summary>
        public X509Name Issuer => m_tbsCertList.Issuer;

        /// <summary>Gets the this update.</summary>
        public Time ThisUpdate => m_tbsCertList.ThisUpdate;

        /// <summary>Gets the next update.</summary>
        public Time NextUpdate => m_tbsCertList.NextUpdate;

        public X509Extensions Extensions => m_tbsCertList.Extensions;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_tbsCertList, m_signatureAlgorithm, m_signatureValue);
    }
}
