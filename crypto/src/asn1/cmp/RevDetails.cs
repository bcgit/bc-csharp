using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * RevDetails ::= SEQUENCE {
     *          certDetails         CertTemplate,
     *          -- allows requester to specify as much as they can about
     *          -- the cert. for which revocation is requested
     *          -- (e.g., for cases in which serialNumber is not available)
     *          crlEntryDetails     Extensions       OPTIONAL
     *          -- requested crlEntryExtensions
     *      }
     * </pre>
     */
    public class RevDetails
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RevDetails"/> from the given object.</summary>
        /// <param name="obj">An <see cref="RevDetails"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="RevDetails"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RevDetails GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RevDetails revDetails)
                return revDetails;
            return new RevDetails(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RevDetails"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevDetails"/>.</returns>
        public static RevDetails GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevDetails(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="RevDetails"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RevDetails"/>.</returns>
        public static RevDetails GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RevDetails(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly CertTemplate m_certDetails;
        private readonly X509Extensions m_crlEntryDetails;

        private RevDetails(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certDetails = Asn1Utilities.Read(seq, ref pos, CertTemplate.GetInstance);
            m_crlEntryDetails = Asn1Utilities.ReadOptional(seq, ref pos, X509Extensions.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="RevDetails"/>.</summary>
        /// <param name="certDetails">The cert details.</param>
        public RevDetails(CertTemplate certDetails)
            : this(certDetails, null)
        {
        }

        /// <summary>Create a new <see cref="RevDetails"/>.</summary>
        /// <param name="certDetails">The cert details.</param>
        /// <param name="crlEntryDetails">The crl entry details.</param>
        public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails)
        {
            m_certDetails = certDetails ?? throw new ArgumentNullException(nameof(certDetails));
            m_crlEntryDetails = crlEntryDetails;
        }

        /// <summary>Gets the cert details.</summary>
        public virtual CertTemplate CertDetails => m_certDetails;

        /// <summary>Gets the crl entry details.</summary>
        public virtual X509Extensions CrlEntryDetails => m_crlEntryDetails;

        /**
        * <pre>
        * RevDetails ::= SEQUENCE {
        *                  certDetails         CertTemplate,
        *                   -- allows requester to specify as much as they can about
        *                   -- the cert. for which revocation is requested
        *                   -- (e.g., for cases in which serialNumber is not available)
        *                   crlEntryDetails     Extensions       OPTIONAL
        *                   -- requested crlEntryExtensions
        *             }
        * </pre>
        * @return a basic ASN.1 object representation.
        */
        public override Asn1Object ToAsn1Object()
        {
            return m_crlEntryDetails == null
                ?  new DerSequence(m_certDetails)
                :  new DerSequence(m_certDetails, m_crlEntryDetails);
        }
    }
}
