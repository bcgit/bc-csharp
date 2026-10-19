using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Esf
{
    /// <summary>The SignerAttribute structure of ETSI TS 101 733.</summary>
    public class SignerAttribute
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SignerAttribute"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="SignerAttribute"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SignerAttribute"/>, or null if <paramref name="obj"/> is null.</returns>
        public static SignerAttribute GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is SignerAttribute signerAttribute)
                return signerAttribute;
            return new SignerAttribute(Asn1Sequence.GetInstance(obj), dummy: true);
        }

        /// <summary>Return an <see cref="SignerAttribute"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerAttribute"/>.</returns>
        public static SignerAttribute GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerAttribute(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="SignerAttribute"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SignerAttribute"/>.</returns>
        public static SignerAttribute GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new SignerAttribute(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_claimedAttributes;
        private readonly AttributeCertificate m_certifiedAttributes;

        private SignerAttribute(Asn1Sequence seq, bool dummy)
        {
            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetContextInstance(seq[0]);
            if (taggedObject.HasTagNo(0))
            {
                m_claimedAttributes = Asn1Sequence.GetTagged(taggedObject, true);
            }
            else if (taggedObject.HasTagNo(1))
            {
                m_certifiedAttributes = AttributeCertificate.GetTagged(taggedObject, true);
            }
            else
            {
                throw new ArgumentException("illegal tag.", nameof(seq));
            }
        }

        /// <summary>Create a new <see cref="SignerAttribute"/>.</summary>
        /// <param name="claimedAttributes">The claimed attributes.</param>
        public SignerAttribute(Asn1Sequence claimedAttributes)
        {
            m_claimedAttributes = claimedAttributes ?? throw new ArgumentNullException(nameof(claimedAttributes));
        }

        /// <summary>Create a new <see cref="SignerAttribute"/>.</summary>
        /// <param name="certifiedAttributes">The certified attributes.</param>
        public SignerAttribute(AttributeCertificate certifiedAttributes)
        {
            m_certifiedAttributes = certifiedAttributes ?? throw new ArgumentNullException(nameof(certifiedAttributes));
        }

        /// <summary>Gets the claimed attributes.</summary>
        public virtual Asn1Sequence ClaimedAttributes => m_claimedAttributes;

        /// <summary>Gets the certified attributes.</summary>
        public virtual AttributeCertificate CertifiedAttributes => m_certifiedAttributes;

        /**
        *
        * <pre>
        *  SignerAttribute ::= SEQUENCE OF CHOICE {
        *      claimedAttributes   [0] ClaimedAttributes,
        *      certifiedAttributes [1] CertifiedAttributes }
        *
        *  ClaimedAttributes ::= SEQUENCE OF Attribute
        *  CertifiedAttributes ::= AttributeCertificate -- as defined in RFC 3281: see clause 4.1.
        * </pre>
        */
        public override Asn1Object ToAsn1Object()
        {
            return m_claimedAttributes != null
                ? new DerSequence(new DerTaggedObject(0, m_claimedAttributes))
                : new DerSequence(new DerTaggedObject(1, m_certifiedAttributes));
        }
    }
}
