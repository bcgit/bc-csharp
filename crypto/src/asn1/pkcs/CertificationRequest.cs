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
    // TODO[api] Stop subclassing this class (and make it sealed)
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

        public static CertificationRequest GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificationRequest(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static CertificationRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificationRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        // TODO[api] make these three private readonly and fix names to match ASN.1
        protected CertificationRequestInfo reqInfo;
        protected AlgorithmIdentifier sigAlgId;
        protected DerBitString sigBits;

        // TODO[api] Remove
        protected CertificationRequest()
        {
        }

        // TODO[api] Fix parameter names to match ASN.1 fields
        public CertificationRequest(CertificationRequestInfo requestInfo, AlgorithmIdentifier algorithm,
            DerBitString signature)
        {
            this.reqInfo = requestInfo ?? throw new ArgumentNullException(nameof(requestInfo));
            this.sigAlgId = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            this.sigBits = signature ?? throw new ArgumentNullException(nameof(signature));
        }

        internal CertificationRequest(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            reqInfo = Asn1Utilities.Read(seq, ref pos, CertificationRequestInfo.GetInstance);
            sigAlgId = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            sigBits = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] Rename as a property
        public CertificationRequestInfo GetCertificationRequestInfo() => reqInfo;

        public AlgorithmIdentifier SignatureAlgorithm => sigAlgId;

        public DerBitString Signature => sigBits;

        public byte[] GetSignatureOctets() => sigBits.GetOctets();

        public override Asn1Object ToAsn1Object() => new DerSequence(reqInfo, sigAlgId, sigBits);
    }
}
