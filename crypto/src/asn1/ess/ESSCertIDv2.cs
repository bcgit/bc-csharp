using System;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Ess
{
    public class EssCertIDv2
        : Asn1Encodable
    {
        private static readonly AlgorithmIdentifier DefaultAlgID = new AlgorithmIdentifier(
            NistObjectIdentifiers.IdSha256);

        public static EssCertIDv2 GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EssCertIDv2 essCertIDv2)
                return essCertIDv2;
            return new EssCertIDv2(Asn1Sequence.GetInstance(obj));
        }

        public static EssCertIDv2 GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EssCertIDv2(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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
                ?? DefaultAlgID;
            m_certHash = Asn1OctetString.GetInstance(seq[pos++]);
            m_issuerSerial = Asn1Utilities.ReadOptional(seq, ref pos, IssuerSerial.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public EssCertIDv2(byte[] certHash)
            : this(null, certHash, null)
        {
        }

        public EssCertIDv2(AlgorithmIdentifier algId, byte[] certHash)
            : this(algId, certHash, null)
        {
        }

        public EssCertIDv2(byte[] certHash, IssuerSerial issuerSerial)
            : this(null, certHash, issuerSerial)
        {
        }

        public EssCertIDv2(AlgorithmIdentifier algId, byte[] certHash, IssuerSerial issuerSerial)
        {
            m_hashAlgorithm = algId ?? DefaultAlgID;
            m_certHash = new DerOctetString(certHash);
            m_issuerSerial = issuerSerial;
        }

        public AlgorithmIdentifier HashAlgorithm => m_hashAlgorithm;

        public byte[] GetCertHash() => Arrays.Clone(m_certHash.GetOctets());

        public IssuerSerial IssuerSerial => m_issuerSerial;

        /**
         * <pre>
         * EssCertIDv2 ::=  SEQUENCE {
         *     hashAlgorithm     AlgorithmIdentifier
         *              DEFAULT {algorithm id-sha256},
         *     certHash          Hash,
         *     issuerSerial      IssuerSerial OPTIONAL
         * }
         *
         * Hash ::= OCTET STRING
         *
         * IssuerSerial ::= SEQUENCE {
         *     issuer         GeneralNames,
         *     serialNumber   CertificateSerialNumber
         * }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            if (!DefaultAlgID.Equals(m_hashAlgorithm))
            {
                v.Add(m_hashAlgorithm);
            }
            v.Add(m_certHash);
            v.AddOptional(m_issuerSerial);
            return new DerSequence(v);
        }
    }
}
