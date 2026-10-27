using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    /// <summary>The RSAPrivateKey structure of PKCS#1.</summary>
    public class RsaPrivateKeyStructure
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RsaPrivateKeyStructure"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RsaPrivateKeyStructure"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RsaPrivateKeyStructure"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RsaPrivateKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RsaPrivateKeyStructure rsaPrivateKeyStructure)
                return rsaPrivateKeyStructure;
            return new RsaPrivateKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RsaPrivateKeyStructure"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsaPrivateKeyStructure"/>.</returns>
        public static RsaPrivateKeyStructure GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new RsaPrivateKeyStructure(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="RsaPrivateKeyStructure"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsaPrivateKeyStructure"/>.</returns>
        public static RsaPrivateKeyStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RsaPrivateKeyStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly BigInteger m_modulus;
        private readonly BigInteger m_publicExponent;
        private readonly BigInteger m_privateExponent;
        private readonly BigInteger m_prime1;
        private readonly BigInteger m_prime2;
        private readonly BigInteger m_exponent1;
        private readonly BigInteger m_exponent2;
        private readonly BigInteger m_coefficient;

        /// <summary>Create a new <see cref="RsaPrivateKeyStructure"/>.</summary>
        /// <param name="modulus">The modulus.</param>
        /// <param name="publicExponent">The public exponent.</param>
        /// <param name="privateExponent">The private exponent.</param>
        /// <param name="prime1">The prime 1.</param>
        /// <param name="prime2">The prime 2.</param>
        /// <param name="exponent1">The exponent 1.</param>
        /// <param name="exponent2">The exponent 2.</param>
        /// <param name="coefficient">The coefficient.</param>
        public RsaPrivateKeyStructure(
            BigInteger modulus,
            BigInteger publicExponent,
            BigInteger privateExponent,
            BigInteger prime1,
            BigInteger prime2,
            BigInteger exponent1,
            BigInteger exponent2,
            BigInteger coefficient)
        {
            m_modulus = modulus ?? throw new ArgumentNullException(nameof(modulus));
            m_publicExponent = publicExponent ?? throw new ArgumentNullException(nameof(publicExponent));
            m_privateExponent = privateExponent ?? throw new ArgumentNullException(nameof(privateExponent));
            m_prime1 = prime1 ?? throw new ArgumentNullException(nameof(prime1));
            m_prime2 = prime2 ?? throw new ArgumentNullException(nameof(prime2));
            m_exponent1 = exponent1 ?? throw new ArgumentNullException(nameof(exponent1));
            m_exponent2 = exponent2 ?? throw new ArgumentNullException(nameof(exponent2));
            m_coefficient = coefficient ?? throw new ArgumentNullException(nameof(coefficient));
        }

        private RsaPrivateKeyStructure(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 9)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            var version = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_modulus = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_publicExponent = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_privateExponent = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_prime1 = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_prime2 = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_exponent1 = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_exponent2 = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;
            m_coefficient = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).Value;

            if (!version.HasValue(0))
                throw new ArgumentException("wrong version for RSA private key");

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Gets the modulus.</summary>
        public BigInteger Modulus => m_modulus;

        /// <summary>Gets the public exponent.</summary>
        public BigInteger PublicExponent => m_publicExponent;

        /// <summary>Gets the private exponent.</summary>
        public BigInteger PrivateExponent => m_privateExponent;

        /// <summary>Gets the prime 1.</summary>
        public BigInteger Prime1 => m_prime1;

        /// <summary>Gets the prime 2.</summary>
        public BigInteger Prime2 => m_prime2;

        /// <summary>Gets the exponent 1.</summary>
        public BigInteger Exponent1 => m_exponent1;

        /// <summary>Gets the exponent 2.</summary>
        public BigInteger Exponent2 => m_exponent2;

        /// <summary>Gets the coefficient.</summary>
        public BigInteger Coefficient => m_coefficient;

        /**
         * This outputs the key in Pkcs1v2 format.
         * <pre>
         *      RsaPrivateKey ::= Sequence {
         *                          version Version,
         *                          modulus Integer, -- n
         *                          publicExponent Integer, -- e
         *                          privateExponent Integer, -- d
         *                          prime1 Integer, -- p
         *                          prime2 Integer, -- q
         *                          exponent1 Integer, -- d mod (p-1)
         *                          exponent2 Integer, -- d mod (q-1)
         *                          coefficient Integer -- (inverse of q) mod p
         *                      }
         *
         *      Version ::= Integer
         * </pre>
         * <p>This routine is written to output Pkcs1 version 0, private keys.</p>
         */
        public override Asn1Object ToAsn1Object()
        {
            return new DerSequence(
                DerInteger.Zero, // version
                new DerInteger(m_modulus),
                new DerInteger(m_publicExponent),
                new DerInteger(m_privateExponent),
                new DerInteger(m_prime1),
                new DerInteger(m_prime2),
                new DerInteger(m_exponent1),
                new DerInteger(m_exponent2),
                new DerInteger(m_coefficient));
        }
    }
}
