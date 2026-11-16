using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <remarks>
    /// RFC 5126: 6.3.4.  revocation-values Attribute Definition
    /// <code>
    /// RevocationValues ::=  SEQUENCE {
    /// crlVals [0] SEQUENCE OF CertificateList     OPTIONAL,
    /// ocspVals [1] SEQUENCE OF BasicOCSPResponse   OPTIONAL,
    /// otherRevVals [2] OtherRevVals OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class RevocationValues
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RevocationValues"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RevocationValues"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RevocationValues"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RevocationValues GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevocationValues revocationValues)
                return revocationValues;
            return new RevocationValues(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RevocationValues"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevocationValues"/>.</returns>
        public static RevocationValues GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new RevocationValues(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="RevocationValues"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevocationValues"/>.</returns>
        public static RevocationValues GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevocationValues(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_crlVals;
        private readonly Asn1Sequence m_ocspVals;
        private readonly OtherRevVals m_otherRevVals;

        private RevocationValues(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_crlVals = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetTagged);
            m_crlVals?.MapElements(CertificateList.GetInstance); // Validate

            m_ocspVals = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, Asn1Sequence.GetTagged);
            m_ocspVals?.MapElements(BasicOcspResponse.GetInstance); // Validate

            m_otherRevVals = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, true, OtherRevVals.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="RevocationValues"/>.</summary>
        /// <param name="crlVals">The crl vals.</param>
        /// <param name="ocspVals">The ocsp vals.</param>
        /// <param name="otherRevVals">The other rev vals.</param>
        public RevocationValues(CertificateList[] crlVals, BasicOcspResponse[] ocspVals, OtherRevVals otherRevVals)
        {
            m_crlVals = DerSequence.FromElementsOptional(crlVals);
            m_ocspVals = DerSequence.FromElementsOptional(ocspVals);
            m_otherRevVals = otherRevVals;
        }

        /// <summary>Create a new <see cref="RevocationValues"/>.</summary>
        /// <param name="crlVals">The crl vals.</param>
        /// <param name="ocspVals">The ocsp vals.</param>
        /// <param name="otherRevVals">The other rev vals.</param>
        public RevocationValues(IEnumerable<CertificateList> crlVals, IEnumerable<BasicOcspResponse> ocspVals,
            OtherRevVals otherRevVals)
        {
            if (crlVals != null)
            {
                m_crlVals = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(crlVals));
            }

            if (ocspVals != null)
            {
                m_ocspVals = DerSequence.FromVector(Asn1EncodableVector.FromEnumerable(ocspVals));
            }

            m_otherRevVals = otherRevVals;
        }

        /// <summary>Create a new <see cref="RevocationValues"/>.</summary>
        /// <param name="crlVals">The crl vals.</param>
        /// <param name="ocspVals">The ocsp vals.</param>
        /// <param name="otherRevVals">The other rev vals.</param>
        public RevocationValues(IReadOnlyCollection<CertificateList> crlVals,
            IReadOnlyCollection<BasicOcspResponse> ocspVals, OtherRevVals otherRevVals)
        {
            if (crlVals != null)
            {
                m_crlVals = DerSequence.FromCollection(crlVals);
            }

            if (ocspVals != null)
            {
                m_ocspVals = DerSequence.FromCollection(ocspVals);
            }

            m_otherRevVals = otherRevVals;
        }

        /// <summary>Return the crl vals.</summary>
        public CertificateList[] GetCrlVals() => m_crlVals?.MapElements(CertificateList.GetInstance);

        /// <summary>Return the ocsp vals.</summary>
        public BasicOcspResponse[] GetOcspVals() => m_ocspVals?.MapElements(BasicOcspResponse.GetInstance);

        /// <summary>Gets the other rev vals.</summary>
        public OtherRevVals OtherRevVals => m_otherRevVals;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_crlVals);
            v.AddOptionalTagged(true, 1, m_ocspVals);
            v.AddOptionalTagged(true, 2, m_otherRevVals);
            return DerSequence.FromVector(v);
        }
    }
}
