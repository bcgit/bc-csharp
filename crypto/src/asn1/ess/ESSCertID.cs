using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Ess
{
    /// <summary>The ESSCertID structure of RFC 2634, identifying a certificate by its SHA-1 hash.</summary>
    public class EssCertID
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="EssCertID"/> from the given object.</summary>
        /// <param name="o">An <see cref="EssCertID"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="EssCertID"/>, or null if <paramref name="o"/> is null.</returns>
        public static EssCertID GetInstance(object o)
        {
            if (o == null)
                return null;
            if (o is EssCertID essCertID)
                return essCertID;
#pragma warning disable CS0618 // Type or member is obsolete
            return new EssCertID(Asn1Sequence.GetInstance(o));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="EssCertID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EssCertID"/>.</returns>
        public static EssCertID GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new EssCertID(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="EssCertID"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EssCertID"/>.</returns>
        public static EssCertID GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new EssCertID(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly Asn1OctetString m_certHash;
        private readonly IssuerSerial m_issuerSerial;

        /// <summary>Create a new <see cref="EssCertID"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public EssCertID(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_certHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_issuerSerial = Asn1Utilities.ReadOptional(seq, ref pos, IssuerSerial.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="EssCertID"/>.</summary>
        /// <param name="hash">The hash.</param>
        public EssCertID(byte[] hash)
            : this(hash, null)
        {
        }

        /// <summary>Create a new <see cref="EssCertID"/>.</summary>
        /// <param name="hash">The hash.</param>
        /// <param name="issuerSerial">The issuer serial.</param>
        public EssCertID(byte[] hash, IssuerSerial issuerSerial)
        {
            m_certHash = DerOctetString.FromContents(hash);
            m_issuerSerial = issuerSerial;
        }

        /// <summary>Create a new <see cref="EssCertID"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="issuerSerial">The issuer serial.</param>
        public EssCertID(Asn1OctetString certHash, IssuerSerial issuerSerial)
        {
            m_certHash = certHash ?? throw new ArgumentNullException(nameof(certHash));
            m_issuerSerial = issuerSerial;
        }

        /// <summary>Gets the cert hash.</summary>
        public Asn1OctetString CertHash => m_certHash;

        /// <summary>Return the cert hash.</summary>
        public byte[] GetCertHash() => Arrays.Clone(m_certHash.GetOctets());

        public IssuerSerial IssuerSerial => m_issuerSerial;

        /**
         * <pre>
         * EssCertID ::= SEQUENCE {
         *     certHash Hash,
         *     issuerSerial IssuerSerial OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_issuerSerial == null
                ?  new DerSequence(m_certHash)
                :  new DerSequence(m_certHash, m_issuerSerial);
        }
    }
}
