using System;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Operators.Utilities;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Ess
{
    /// <remarks>
    /// <code>
    /// EssCertIDv2 ::=  SEQUENCE {
    ///     hashAlgorithm   AlgorithmIdentifier DEFAULT { algorithm id-sha256},
    ///     certHash        Hash,
    ///     issuerSerial    IssuerSerial OPTIONAL
    /// }
    ///
    /// Hash ::= OCTET STRING
    /// </code>
    /// </remarks>
    public class EssCertIDv2
        : Asn1Encodable
    {
        private static readonly AlgorithmIdentifier DefaultHashAlgorithm =
            DefaultDigestAlgorithmFinder.Instance.Find(NistObjectIdentifiers.IdSha256);
        private static readonly AlgorithmIdentifier V1HashAlgorithm =
            new AlgorithmIdentifier(OiwObjectIdentifiers.IdSha1);

        public static EssCertIDv2 From(EssCertID essCertID) =>
            new EssCertIDv2(V1HashAlgorithm, essCertID.CertHash, essCertID.IssuerSerial);

        /// <summary>Return an <see cref="EssCertIDv2"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="EssCertIDv2"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="EssCertIDv2"/>, or null if <paramref name="obj"/> is null.</returns>
        public static EssCertIDv2 GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EssCertIDv2 essCertIDv2)
                return essCertIDv2;
            return new EssCertIDv2(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="EssCertIDv2"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EssCertIDv2"/>.</returns>
        public static EssCertIDv2 GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EssCertIDv2(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="EssCertIDv2"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="EssCertIDv2"/>.</returns>
        public static EssCertIDv2 GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EssCertIDv2(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly Asn1OctetString m_certHash;
        private readonly IssuerSerial m_issuerSerial;

        private EssCertIDv2(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_hashAlgorithm = Asn1Utilities.ReadOptional(seq, ref pos, AlgorithmIdentifier.GetOptional)
                ?? DefaultHashAlgorithm;
            m_certHash = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_issuerSerial = Asn1Utilities.ReadOptional(seq, ref pos, IssuerSerial.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="EssCertIDv2"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        public EssCertIDv2(byte[] certHash)
            : this(null, certHash, null)
        {
        }

        /// <summary>Create a new <see cref="EssCertIDv2"/>.</summary>
        /// <param name="algId">The alg id.</param>
        /// <param name="certHash">The cert hash.</param>
        public EssCertIDv2(AlgorithmIdentifier algId, byte[] certHash)
            : this(algId, certHash, null)
        {
        }

        /// <summary>Create a new <see cref="EssCertIDv2"/>.</summary>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="issuerSerial">The issuer serial.</param>
        public EssCertIDv2(byte[] certHash, IssuerSerial issuerSerial)
            : this(null, certHash, issuerSerial)
        {
        }

        /// <summary>Create a new <see cref="EssCertIDv2"/>.</summary>
        /// <param name="algId">The alg id.</param>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="issuerSerial">The issuer serial.</param>
        public EssCertIDv2(AlgorithmIdentifier algId, byte[] certHash, IssuerSerial issuerSerial)
        {
            m_hashAlgorithm = algId ?? DefaultHashAlgorithm;
            m_certHash = DerOctetString.FromContents(certHash);
            m_issuerSerial = issuerSerial;
        }

        /// <summary>Create a new <see cref="EssCertIDv2"/>.</summary>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="certHash">The cert hash.</param>
        /// <param name="issuerSerial">The issuer serial.</param>
        public EssCertIDv2(AlgorithmIdentifier hashAlgorithm, Asn1OctetString certHash, IssuerSerial issuerSerial)
        {
            m_hashAlgorithm = hashAlgorithm ?? DefaultHashAlgorithm;
            m_certHash = certHash ?? throw new ArgumentNullException(nameof(certHash));
            m_issuerSerial = issuerSerial;
        }

        /// <summary>Gets the hash algorithm.</summary>
        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        /// <summary>Gets the cert hash.</summary>
        public Asn1OctetString CertHash => m_certHash;

        /// <summary>Return the cert hash.</summary>
        public byte[] GetCertHash() => Arrays.Clone(m_certHash.GetOctets());

        /// <summary>Gets the issuer serial.</summary>
        public IssuerSerial IssuerSerial => m_issuerSerial;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            if (!DefaultHashAlgorithm.Equals(m_hashAlgorithm))
            {
                v.Add(m_hashAlgorithm);
            }
            v.Add(m_certHash);
            v.AddOptional(m_issuerSerial);
            return new DerSequence(v);
        }
    }
}
