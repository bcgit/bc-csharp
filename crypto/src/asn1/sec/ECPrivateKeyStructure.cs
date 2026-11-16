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
        /// <summary>Return an <see cref="ECPrivateKeyStructure"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="ECPrivateKeyStructure"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="ECPrivateKeyStructure"/>, or null if <paramref name="obj"/> is null.</returns>
        public static ECPrivateKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ECPrivateKeyStructure ecPrivateKeyStructure)
                return ecPrivateKeyStructure;
            return new ECPrivateKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="ECPrivateKeyStructure"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ECPrivateKeyStructure"/>.</returns>
        public static ECPrivateKeyStructure GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ECPrivateKeyStructure(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="ECPrivateKeyStructure"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="ECPrivateKeyStructure"/>.</returns>
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

            m_version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_privateKey = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_parameters = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true,
                (t, e) => t.GetExplicitBaseObject());
            m_publicKey = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, true, DerBitString.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="ECPrivateKeyStructure"/>.</summary>
        /// <param name="orderBitLength">The order bit length.</param>
        /// <param name="key">The key.</param>
        public ECPrivateKeyStructure(int orderBitLength, BigInteger key)
            : this(orderBitLength, key, null)
        {
        }

        /// <summary>Create a new <see cref="ECPrivateKeyStructure"/>.</summary>
        /// <param name="orderBitLength">The order bit length.</param>
        /// <param name="key">The key.</param>
        /// <param name="parameters">The parameters.</param>
        public ECPrivateKeyStructure(int orderBitLength, BigInteger key, Asn1Encodable parameters)
            : this(orderBitLength, key, null, parameters)
        {
        }

        /// <summary>Create a new <see cref="ECPrivateKeyStructure"/>.</summary>
        /// <param name="orderBitLength">The order bit length.</param>
        /// <param name="key">The key.</param>
        /// <param name="publicKey">The public key.</param>
        /// <param name="parameters">The parameters.</param>
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

        /// <summary>Create a new <see cref="ECPrivateKeyStructure"/>.</summary>
        /// <param name="privateKey">The private key.</param>
        /// <param name="parameters">The parameters.</param>
        /// <param name="publicKey">The public key.</param>
        public ECPrivateKeyStructure(Asn1OctetString privateKey, Asn1Encodable parameters, DerBitString publicKey)
        {
            m_version = DerInteger.One;
            m_privateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            m_parameters = parameters;
            m_publicKey = publicKey;
        }

        /// <summary>Gets the version.</summary>
        public DerInteger Version => m_version;

        /// <summary>Gets the private key.</summary>
        public Asn1OctetString PrivateKey => m_privateKey;

        /// <summary>Gets the parameters.</summary>
        public Asn1Encodable Parameters => m_parameters;

        /// <summary>Gets the public key.</summary>
        public DerBitString PublicKey => m_publicKey;

        /// <summary>Return the key.</summary>
        public virtual BigInteger GetKey() => BigIntegers.FromUnsignedByteArray(m_privateKey.GetOctets());

        /// <summary>Return the public key.</summary>
        [Obsolete("Use 'PublicKey' instead")]
        public virtual DerBitString GetPublicKey() => m_publicKey;

        /// <summary>Return the parameters.</summary>
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
