using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The Signature structure of RFC 6960.</summary>
    public class Signature
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Signature"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Signature"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Signature"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Signature GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Signature signature)
                return signature;
            return new Signature(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Signature"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Signature"/>.</returns>
        public static Signature GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Signature(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="Signature"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Signature"/>.</returns>
        public static Signature GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Signature(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_signatureAlgorithm;
        private readonly DerBitString m_signatureValue;
        private readonly Asn1Sequence m_certs;

        /// <summary>Create a new <see cref="Signature"/>.</summary>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <param name="signatureValue">The signature value.</param>
        public Signature(AlgorithmIdentifier signatureAlgorithm, DerBitString signatureValue)
            : this(signatureAlgorithm, signatureValue, null)
        {
        }

        /// <summary>Create a new <see cref="Signature"/>.</summary>
        /// <param name="signatureAlgorithm">The signature algorithm.</param>
        /// <param name="signatureValue">The signature value.</param>
        /// <param name="certs">The certs.</param>
        public Signature(AlgorithmIdentifier signatureAlgorithm, DerBitString signatureValue, Asn1Sequence certs)
        {
            m_signatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            m_signatureValue = signatureValue ?? throw new ArgumentNullException(nameof(signatureValue));
            m_certs = certs;
        }

        private Signature(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            int pos = 0;

            m_signatureAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_signatureValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);
            m_certs = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, Asn1Sequence.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => m_signatureAlgorithm;

        /// <summary>Gets the signature value.</summary>
        public DerBitString SignatureValue => m_signatureValue;

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignatureOctets() => m_signatureValue.GetOctets();

        /// <summary>Gets the certs.</summary>
        public Asn1Sequence Certs => m_certs;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * Signature       ::=     Sequence {
         *     signatureAlgorithm      AlgorithmIdentifier,
         *     signature               BIT STRING,
         *     certs               [0] EXPLICIT Sequence OF Certificate OPTIONAL}
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_signatureAlgorithm, m_signatureValue);
            v.AddOptionalTagged(true, 0, m_certs);
            return new DerSequence(v);
        }
    }
}
