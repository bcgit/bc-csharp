using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /// <summary>The CertStatus structure of RFC 4210: the confirmation of a single certificate.</summary>
    public class CertStatus
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CertStatus"/> from the given object.</summary>
        /// <param name="obj">An <see cref="CertStatus"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="CertStatus"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CertStatus GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CertStatus certStatus)
                return certStatus;
            return new CertStatus(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CertStatus"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertStatus"/>.</returns>
        public static CertStatus GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertStatus(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="CertStatus"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CertStatus"/>.</returns>
        public static CertStatus GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CertStatus(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_certHash;
        private readonly DerInteger m_certReqID;
        private readonly PkiStatusInfo m_statusInfo;
        private readonly AlgorithmIdentifier m_hashAlg;

        private CertStatus(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_certReqID = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_statusInfo = Asn1Utilities.ReadOptional(seq, ref pos, PkiStatusInfo.GetOptional);
            m_hashAlg = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true, AlgorithmIdentifier.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="certReqID">The cert req ID.</param>
        public CertStatus(byte[] certHash, BigInteger certReqID)
            : this(certHash, certReqID, null, null)
        {
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="certReqID">The cert req ID.</param>
        public CertStatus(byte[] certHash, DerInteger certReqID)
        {
            m_certHash = DerOctetString.FromContents(certHash);
            m_certReqID = certReqID;
            m_statusInfo = null;
            m_hashAlg = null;
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="certReqID">The cert req ID.</param>
        /// <param name="statusInfo">The status info.</param>
        public CertStatus(byte[] certHash, BigInteger certReqID, PkiStatusInfo statusInfo)
        {
            m_certHash = DerOctetString.FromContents(certHash);
            m_certReqID = new DerInteger(certReqID);
            m_statusInfo = statusInfo;
            m_hashAlg = null;
        }

        /// <summary>Create a new <see cref="CertStatus"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="certReqID">The cert req ID.</param>
        /// <param name="statusInfo">The status info.</param>
        /// <param name="hashAlg">The hash alg.</param>
        public CertStatus(byte[] certHash, BigInteger certReqID, PkiStatusInfo statusInfo, AlgorithmIdentifier hashAlg)
        {
            m_certHash = DerOctetString.FromContents(certHash);
            m_certReqID = new DerInteger(certReqID);
            m_statusInfo = statusInfo;
            m_hashAlg = hashAlg;
        }

        /// <summary>Gets the cert hash.</summary>
        public virtual Asn1OctetString CertHash => m_certHash;

        /// <summary>Gets the cert req ID.</summary>
        public virtual DerInteger CertReqID => m_certReqID;

        public virtual PkiStatusInfo StatusInfo => m_statusInfo;

        /// <summary>Gets the hash alg.</summary>
        public virtual AlgorithmIdentifier HashAlg => m_hashAlg;

        /**
         * <pre>
         *
         *  CertStatus ::= SEQUENCE {
         *     certHash    OCTET STRING,
         *     certReqId   INTEGER,
         *     statusInfo  PKIStatusInfo OPTIONAL,
         *     hashAlg [0] AlgorithmIdentifier{DIGEST-ALGORITHM, {...}} OPTIONAL
         *   }
         *
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_certHash, m_certReqID);
            v.AddOptional(m_statusInfo);
            v.AddOptionalTagged(true, 0, m_hashAlg);
            return new DerSequence(v);
        }
    }
}
