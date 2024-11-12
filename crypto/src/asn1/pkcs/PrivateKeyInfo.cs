using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /**
     *  RFC 5958
     *
     *  <pre>
     *  [IMPLICIT TAGS]
     *
     *  OneAsymmetricKey ::= SEQUENCE {
     *      version                   Version,
     *      privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
     *      privateKey                PrivateKey,
     *      attributes            [0] Attributes OPTIONAL,
     *      ...,
     *      [[2: publicKey        [1] PublicKey OPTIONAL ]],
     *      ...
     *  }
     *
     *  PrivateKeyInfo ::= OneAsymmetricKey
     *
     *  Version ::= INTEGER { v1(0), v2(1) } (v1, ..., v2)
     *
     *  PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     *                                     { PUBLIC-KEY,
     *                                       { PrivateKeyAlgorithms } }
     *
     *  PrivateKey ::= OCTET STRING
     *                     -- Content varies based on type of key.  The
     *                     -- algorithm identifier dictates the format of
     *                     -- the key.
     *
     *  PublicKey ::= BIT STRING
     *                     -- Content varies based on type of key.  The
     *                     -- algorithm identifier dictates the format of
     *                     -- the key.
     *
     *  Attributes ::= SET OF Attribute { { OneAsymmetricKeyAttributes } }
     *  </pre>
     */
    public class PrivateKeyInfo
        : Asn1Encodable
    {
        public static PrivateKeyInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PrivateKeyInfo privateKeyInfo)
                return privateKeyInfo;
            return new PrivateKeyInfo(Asn1Sequence.GetInstance(obj));
        }

        public static PrivateKeyInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new PrivateKeyInfo(Asn1Sequence.GetInstance(obj, explicitly));

        public static PrivateKeyInfo GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PrivateKeyInfo privateKeyInfo)
                return privateKeyInfo;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new PrivateKeyInfo(asn1Sequence);

            return null;
        }

        public static PrivateKeyInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PrivateKeyInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_privateKeyAlgorithm;
        private readonly Asn1OctetString m_privateKey;
        private readonly Asn1Set m_attributes;
        private readonly DerBitString m_publicKey;

        private PrivateKeyInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_privateKeyAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
            m_privateKey = Asn1OctetString.GetInstance(seq[pos++]);
            m_attributes = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, Asn1Set.GetTagged);
            m_publicKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerBitString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            int versionValue = GetVersionValue(m_version);

            if (m_publicKey != null && versionValue < 1)
                throw new ArgumentException("'publicKey' requires version v2(1) or later", nameof(seq));
        }

        public PrivateKeyInfo(AlgorithmIdentifier privateKeyAlgorithm, Asn1Encodable privateKey)
            : this(privateKeyAlgorithm, privateKey, null, null)
        {
        }

        public PrivateKeyInfo(AlgorithmIdentifier privateKeyAlgorithm, Asn1Encodable privateKey, Asn1Set attributes)
            : this(privateKeyAlgorithm, privateKey, attributes, null)
        {
        }

        public PrivateKeyInfo(AlgorithmIdentifier privateKeyAlgorithm, Asn1Encodable privateKey, Asn1Set attributes,
            byte[] publicKey)
        {
            m_version = new DerInteger(publicKey != null ? 1 : 0);
            m_privateKeyAlgorithm = privateKeyAlgorithm ?? throw new ArgumentNullException(nameof(privateKeyAlgorithm));
            m_privateKey = new DerOctetString(privateKey);
            m_attributes = attributes;
            m_publicKey = publicKey == null ? null : new DerBitString(publicKey);
        }

        public virtual DerInteger Version => m_version;

        public virtual Asn1Set Attributes => m_attributes;

        /// <summary>Return true if a public key is present, false otherwise.</summary>
        public virtual bool HasPublicKey => m_publicKey != null;

        public virtual AlgorithmIdentifier PrivateKeyAlgorithm => m_privateKeyAlgorithm;

        public virtual Asn1OctetString PrivateKey => m_privateKey;

        [Obsolete("Use 'PrivateKey' instead")]
        public virtual Asn1OctetString PrivateKeyData => m_privateKey;

        public virtual int PrivateKeyLength => m_privateKey.GetOctetsLength();

        public virtual Asn1Object ParsePrivateKey() => Asn1Object.FromByteArray(m_privateKey.GetOctets());

        /// <summary>For when the public key is an ASN.1 encoding.</summary>
        public virtual Asn1Object ParsePublicKey()
        {
            return m_publicKey == null ? null : Asn1Object.FromMemoryStream(m_publicKey.GetOctetMemoryStream());
        }

        public virtual DerBitString PublicKey => m_publicKey;

        /// <summary>Return the public key as a raw bit string.</summary>
        [Obsolete("Use 'PublicKey' instead")]
        public virtual DerBitString PublicKeyData => m_publicKey;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_version, m_privateKeyAlgorithm, m_privateKey);
            v.AddOptionalTagged(false, 0, m_attributes);
            v.AddOptionalTagged(false, 1, m_publicKey);
            return new DerSequence(v);
        }

        private static int GetVersionValue(DerInteger version)
        {
            if (version.TryGetIntPositiveValueExact(out int value))
            {
                if (value >= 0 && value <= 1)
                    return value;
            }

            throw new ArgumentException("Invalid version for PrivateKeyInfo", nameof(version));
        }
    }
}
