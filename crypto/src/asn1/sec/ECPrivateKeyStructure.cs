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
        private readonly Asn1Sequence m_seq;

        public static ECPrivateKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ECPrivateKeyStructure ecPrivateKeyStructure)
                return ecPrivateKeyStructure;
            return new ECPrivateKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        private ECPrivateKeyStructure(Asn1Sequence seq)
        {
            m_seq = seq ?? throw new ArgumentNullException(nameof(seq));
        }

        public ECPrivateKeyStructure(
            int         orderBitLength,
            BigInteger  key)
            : this(orderBitLength, key, null)
        {
        }

        public ECPrivateKeyStructure(
            int             orderBitLength,
            BigInteger      key,
            Asn1Encodable   parameters)
            : this(orderBitLength, key, null, parameters)
        {
        }

        public ECPrivateKeyStructure(
            int             orderBitLength,
            BigInteger      key,
            DerBitString    publicKey,
            Asn1Encodable   parameters)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (orderBitLength < key.BitLength)
                throw new ArgumentException("must be >= key bitlength", nameof(orderBitLength));

            byte[] bytes = BigIntegers.AsUnsignedByteArray((orderBitLength + 7) / 8, key);

            Asn1EncodableVector v = new Asn1EncodableVector(
                DerInteger.One,
                new DerOctetString(bytes));

            v.AddOptionalTagged(true, 0, parameters);
            v.AddOptionalTagged(true, 1, publicKey);

            m_seq = new DerSequence(v);
        }

        public virtual BigInteger GetKey()
        {
            Asn1OctetString octs = (Asn1OctetString)m_seq[1];

            return new BigInteger(1, octs.GetOctets());
        }

        public virtual DerBitString GetPublicKey()
        {
            return (DerBitString)GetObjectInTag(1, Asn1Tags.BitString);
        }

        public virtual Asn1Object GetParameters()
        {
            return GetObjectInTag(0, -1);
        }

        private Asn1Object GetObjectInTag(int tagNo, int baseTagNo)
        {
            foreach (Asn1Encodable ae in m_seq)
            {
                Asn1Object obj = ae.ToAsn1Object();

                if (obj is Asn1TaggedObject tag)
                {
                    if (tag.HasContextTag(tagNo))
                    {
                        return baseTagNo < 0
                            ? tag.GetExplicitBaseObject().ToAsn1Object()
                            : tag.GetBaseUniversal(true, baseTagNo);
                    }
                }
            }

            return null;
        }

        /**
         * ECPrivateKey ::= SEQUENCE {
         *     version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
         *     privateKey OCTET STRING,
         *     parameters [0] Parameters OPTIONAL,
         *     publicKey [1] BIT STRING OPTIONAL }
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_seq;
        }
    }
}
