using System;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.Sec
{
    /**
     * the elliptic curve private key object from SEC 1
     */
    public class ECPrivateKeyStructure
        : Asn1Encodable
    {
        public static ECPrivateKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ECPrivateKeyStructure ecPrivateKeyStructure)
                return ecPrivateKeyStructure;
            return new ECPrivateKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        public static ECPrivateKeyStructure GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ECPrivateKeyStructure(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ECPrivateKeyStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ECPrivateKeyStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Asn1OctetString m_privateKey;
        private readonly Asn1Encodable m_parameters;
        private readonly DerBitString m_publicKey;

        private ECPrivateKeyStructure(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_privateKey = Asn1OctetString.GetInstance(seq[pos++]);
            m_parameters = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true,
                (t, e) => t.GetExplicitBaseObject());
            m_publicKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, DerBitString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public ECPrivateKeyStructure(int orderBitLength, BigInteger key)
            : this(orderBitLength, key, null)
        {
        }

        public ECPrivateKeyStructure(int orderBitLength, BigInteger key, Asn1Encodable parameters)
            : this(orderBitLength, key, null, parameters)
        {
        }

        public ECPrivateKeyStructure(int orderBitLength, BigInteger key, DerBitString publicKey,
            Asn1Encodable parameters)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (orderBitLength < key.BitLength)
                throw new ArgumentException("must be >= key bitlength", nameof(orderBitLength));

            byte[] privateKeyContents = BigIntegers.AsUnsignedByteArray((orderBitLength + 7) / 8, key);

            m_version = DerInteger.One;
            m_privateKey = new DerOctetString(privateKeyContents);
            m_parameters = parameters;
            m_publicKey = publicKey;
        }

        public DerInteger Version => m_version;

        public Asn1OctetString PrivateKey => m_privateKey;

        public Asn1Encodable Parameters => m_parameters;

        public DerBitString PublicKey => m_publicKey;

        public virtual BigInteger GetKey() => BigIntegers.FromUnsignedByteArray(m_privateKey.GetOctets());

        [Obsolete("Use 'PublicKey' instead")]
        public virtual DerBitString GetPublicKey() => m_publicKey;

        [Obsolete("Use 'Parameters' instead")]
        public virtual Asn1Object GetParameters() => m_parameters?.ToAsn1Object();

        /**
         * ECPrivateKey ::= SEQUENCE {
         *     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
         *     privateKey OCTET STRING,
         *     parameters [0] Parameters OPTIONAL,
         *     publicKey [1] BIT STRING OPTIONAL }
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_version, m_privateKey);
            v.AddOptionalTagged(true, 0, m_parameters);
            v.AddOptionalTagged(true, 1, m_publicKey);
            return new DerSequence(v);
        }
    }
}
