using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.IsisMtt.Ocsp
{
    /**
    * ISIS-MTT PROFILE: The responder may include this extension in a response to
    * send the hash of the requested certificate to the responder. This hash is
    * cryptographically bound to the certificate and serves as evidence that the
    * certificate is known to the responder (i.e. it has been issued and is present
    * in the directory). Hence, this extension is a means to provide a positive
    * statement of availability as described in T8.[8]. As explained in T13.[1],
    * clients may rely on this information to be able to validate signatures after
    * the expiry of the corresponding certificate. Hence, clients MUST support this
    * extension. If a positive statement of availability is to be delivered, this
    * extension syntax and OID MUST be used.
    * <p/>
    * <p/>
    * <pre>
    *     CertHash ::= SEQUENCE {
    *       hashAlgorithm AlgorithmIdentifier,
    *       certificateHash OCTET STRING
    *     }
    * </pre>
    */
    public class CertHash
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertHash"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertHash"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertHash"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertHash GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertHash certHash)
                return certHash;
            return new CertHash(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertHash"/>.</returns>
        public static CertHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertHash(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertHash"/>.</returns>
        public static CertHash GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertHash(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_certificateHash;

        /**
        * Constructor from Asn1Sequence.
        * <p/>
        * The sequence is of type CertHash:
        * <p/>
        * <pre>
        *     CertHash ::= SEQUENCE {
        *       hashAlgorithm AlgorithmIdentifier,
        *       certificateHash OCTET STRING
        *     }
        * </pre>
        *
        * @param seq The ASN.1 sequence.
        */
        private CertHash(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_certificateHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
        * Constructor from a given details.
        *
        * @param hashAlgorithm   The hash algorithm identifier.
        * @param certificateHash The hash of the whole DER encoding of the certificate.
        */
        public CertHash(AlgorithmIdentifier hashAlgorithm, byte[] certificateHash)
        {
            m_hashAlgorithm = hashAlgorithm ?? throw new ArgumentNullException(nameof(hashAlgorithm));
            m_certificateHash = DerOctetString.FromContents(certificateHash);
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the certificate hash.</summary>
        public byte[] CertificateHash => Arrays.Clone(m_certificateHash.GetOctets());

        /**
        * Produce an object suitable for an Asn1OutputStream.
        * <p/>
        * Returns:
        * <p/>
        * <pre>
        *     CertHash ::= SEQUENCE {
        *       hashAlgorithm AlgorithmIdentifier,
        *       certificateHash OCTET STRING
        *     }
        * </pre>
        *
        * @return an Asn1Object
        */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_hashAlgorithm, m_certificateHash);
    }
}
