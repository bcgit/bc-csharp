using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Ess
{
    /// <summary>The SigningCertificate structure of RFC 2634.</summary>
    public class SigningCertificate
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="SigningCertificate"/> from the given object.</summary>
        /// <param name="o">
        /// An <see cref="SigningCertificate"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="SigningCertificate"/>, or null if <paramref name="o"/> is null.</returns>
        public static SigningCertificate GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is SigningCertificate signingCertificate)
                return signingCertificate;
#pragma warning disable CS0618 // Type or member is obsolete
            return new SigningCertificate(Asn1Sequence.GetInstance(o));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SigningCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SigningCertificate"/>.</returns>
        public static SigningCertificate GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SigningCertificate(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="SigningCertificate"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="SigningCertificate"/>.</returns>
        public static SigningCertificate GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new SigningCertificate(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1Sequence m_certs;
        private readonly Asn1Sequence m_policies;

        /// <summary>Create a new <see cref="SigningCertificate"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public SigningCertificate(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certs = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);
            m_policies = Asn1Utilities.ReadOptional(seq, ref pos, Asn1Sequence.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="SigningCertificate"/>.</summary>
        /// <param name="essCertID">The ess cert ID.</param>
        public SigningCertificate(EssCertID essCertID)
        {
            m_certs = new DerSequence(essCertID);
        }

        /// <summary>Return the certs.</summary>
        public EssCertID[] GetCerts() => m_certs.MapElements(EssCertID.GetInstance);

        /// <summary>Return the policies.</summary>
        public PolicyInformation[] GetPolicies() => m_policies?.MapElements(PolicyInformation.GetInstance);

        /**
         * The definition of SigningCertificate is
         * <pre>
         * SigningCertificate ::=  SEQUENCE {
         *      certs        SEQUENCE OF EssCertID,
         *      policies     SEQUENCE OF PolicyInformation OPTIONAL
         * }
         * </pre>
         * id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
         *  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
         *  smime(16) id-aa(2) 12 }
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_policies == null
                ?  DerSequence.FromElement(m_certs)
                :  DerSequence.FromElements(m_certs, m_policies);
        }
    }
}
