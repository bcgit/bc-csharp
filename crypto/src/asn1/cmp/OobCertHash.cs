using System;

using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * OOBCertHash ::= SEQUENCE {
     * hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
     * certId      [1] CertId                  OPTIONAL,
     * hashVal         BIT STRING
     * -- hashVal is calculated over the DER encoding of the
     * -- self-signed certificate with the identifier certID.
     * }
     * </pre>
     */
    public class OobCertHash
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="OobCertHash"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="OobCertHash"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="OobCertHash"/>, or null if <paramref name="obj"/> is null.</returns>
        public static OobCertHash GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is OobCertHash oobCertHash)
                return oobCertHash;
            return new OobCertHash(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="OobCertHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OobCertHash"/>.</returns>
        public static OobCertHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OobCertHash(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="OobCertHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="OobCertHash"/>.</returns>
        public static OobCertHash GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new OobCertHash(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlg;
        private readonly CertId m_certId;
        private readonly DerBitString m_hashVal;

        private OobCertHash(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetTagged);
            m_certId = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, CertId.GetTagged);
            m_hashVal = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="OobCertHash"/>.</summary>
        /// <param name="hashAlg">The hash alg.</param>
        /// <param name="certId">The cert id.</param>
        /// <param name="hashVal">The hash val.</param>
        public OobCertHash(AlgorithmIdentifier hashAlg, CertId certId, DerBitString hashVal)
        {
            m_hashAlg = hashAlg;
            m_certId = certId;
            m_hashVal = hashVal ?? throw new ArgumentNullException(nameof(hashVal));
        }

        /// <summary>Gets the cert ID.</summary>
        public virtual CertId CertID => m_certId;

        /// <summary>Gets the hash alg.</summary>
        public virtual AlgorithmIdentifier HashAlg => m_hashAlg;

        /// <summary>Gets the hash val.</summary>
        public virtual DerBitString HashVal => m_hashVal;

        /**
         * <pre>
         * OobCertHash ::= SEQUENCE {
         *                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
         *                      certId      [1] CertId                  OPTIONAL,
         *                      hashVal         BIT STRING
         *                      -- hashVal is calculated over the Der encoding of the
         *                      -- self-signed certificate with the identifier certID.
         *       }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_hashAlg);
            v.AddOptionalTagged(true, 1, m_certId);
            v.Add(m_hashVal);
            return new DerSequence(v);
        }
    }
}
