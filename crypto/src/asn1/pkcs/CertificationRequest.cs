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
        /// <summary>Return an <see cref="CertificationRequest"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CertificationRequest"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CertificationRequest"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertificationRequest GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertificationRequest certificationRequest)
                return certificationRequest;
            return new CertificationRequest(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertificationRequest"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificationRequest"/>.</returns>
        public static CertificationRequest GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificationRequest(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertificationRequest"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertificationRequest"/>.</returns>
        public static CertificationRequest GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertificationRequest(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        // TODO[api] make these three private readonly and fix names to match ASN.1
        protected CertificationRequestInfo reqInfo;
        protected AlgorithmIdentifier sigAlgId;
        protected DerBitString sigBits;

        /// <summary>Create a new <see cref="CertificationRequest"/>.</summary>
        // TODO[api] Remove
        protected CertificationRequest()
        {
        }

        /// <summary>Create a new <see cref="CertificationRequest"/>.</summary>
        /// <param name="requestInfo">The request info.</param>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="signature">The signature.</param>
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

        /// <summary>Return the certification request info.</summary>
        // TODO[api] Rename as a property
        public CertificationRequestInfo GetCertificationRequestInfo() => reqInfo;

        /// <summary>Gets the signature algorithm.</summary>
        public AlgorithmIdentifier SignatureAlgorithm => sigAlgId;

        /// <summary>Gets the signature.</summary>
        public DerBitString Signature => sigBits;

        /// <summary>Return the signature octets.</summary>
        public byte[] GetSignatureOctets() => sigBits.GetOctets();

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(reqInfo, sigAlgId, sigBits);
    }
}
