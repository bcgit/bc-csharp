using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The AttributeCertificate structure of RFC 5755.</summary>
    public class AttributeCertificate
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AttributeCertificate"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AttributeCertificate"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AttributeCertificate"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AttributeCertificate GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AttributeCertificate attributeCertificate)
                return attributeCertificate;
            return new AttributeCertificate(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AttributeCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributeCertificate"/>.</returns>
        public static AttributeCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AttributeCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AttributeCertificate"/>.</returns>
        public static AttributeCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AttributeCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AttributeCertificateInfo m_acinfo;
        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signatureValue;

        private AttributeCertificate(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_acinfo = Asn1Utilities.Read(seq, ref pos, AttributeCertificateInfo.GetInstance);
            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signatureValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="AttributeCertificate"/>.</summary>
        /// <param name="acinfo">The acinfo.</param>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <param name="signatureValue">The signature value.</param>
        public AttributeCertificate(AttributeCertificateInfo acinfo, AlgorithmIdentifier signatureAlgorithm,
            DerBitString signatureValue)
        {
            m_acinfo = acinfo ?? throw new ArgumentNullException(nameof(acinfo));
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
        }

        /// <summary>Gets the AC info.</summary>
        public AttributeCertificateInfo ACInfo => m_acinfo;

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        /// <summary>Gets the signature value.</summary>
        public DerBitString SignatureValue => m_signatureValue;

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignatureOctets() => m_signatureValue.GetOctets();

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *  AttributeCertificate ::= Sequence {
         *       acinfo               AttributeCertificateInfo,
         *       signatureAlgorithm   AlgorithmIdentifier,
         *       signatureValue       BIT STRING
         *  }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_acinfo, m_signatureAlgorithm, m_signatureValue);
    }
}
