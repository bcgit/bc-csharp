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
        public static CertHash GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertHash certHash)
                return certHash;
            return new CertHash(Asn1Sequence.GetInstance(obj));
        }

        public static CertHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertHash(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = AlgorithmIdentifier.GetInstance(seq[0]);
            m_certificateHash = Asn1OctetString.GetInstance(seq[1]);
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
			m_certificateHash = new DerOctetString(certificateHash);
		}

		public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

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
