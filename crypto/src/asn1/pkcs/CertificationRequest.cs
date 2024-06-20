using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     * Pkcs10 Certfication request object.
     * <pre>
     * CertificationRequest ::= Sequence {
     *   certificationRequestInfo  CertificationRequestInfo,
     *   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
     *   signature                 BIT STRING
     * }
     * </pre>
     */
    // TODO[api] Stop subclassing this class
    public class CertificationRequest
        : Asn1Encodable
    {
		public static CertificationRequest GetInstance(object obj)
		{
            if (obj == null)
                return null;
            if (obj is CertificationRequest certificationRequest)
				return certificationRequest;
            return new CertificationRequest(Asn1Sequence.GetInstance(obj));
		}

        public static CertificationRequest GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new CertificationRequest(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        protected CertificationRequestInfo reqInfo;
        protected AlgorithmIdentifier sigAlgId;
        protected DerBitString sigBits;

        protected CertificationRequest()
        {
        }

        public CertificationRequest(CertificationRequestInfo requestInfo, AlgorithmIdentifier algorithm,
            DerBitString signature)
        {
            this.reqInfo = requestInfo;
            this.sigAlgId = algorithm;
            this.sigBits = signature;
        }

        internal CertificationRequest(Asn1Sequence seq)
        {
			if (seq.Count != 3)
				throw new ArgumentException("Wrong number of elements in sequence", "seq");

			reqInfo = CertificationRequestInfo.GetInstance(seq[0]);
            sigAlgId = AlgorithmIdentifier.GetInstance(seq[1]);
            sigBits = DerBitString.GetInstance(seq[2]);
        }

        // TODO[api] Rename as a property
        public CertificationRequestInfo GetCertificationRequestInfo() => reqInfo;

		public AlgorithmIdentifier SignatureAlgorithm => sigAlgId;

		public DerBitString Signature => sigBits;

        public byte[] GetSignatureOctets() => sigBits.GetOctets();

        public override Asn1Object ToAsn1Object() => new DerSequence(reqInfo, sigAlgId, sigBits);
    }
}
