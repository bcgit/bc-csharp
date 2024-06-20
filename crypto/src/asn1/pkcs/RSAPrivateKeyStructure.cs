using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class RsaPrivateKeyStructure
        : Asn1Encodable
    {
        public static RsaPrivateKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RsaPrivateKeyStructure rsaPrivateKeyStructure)
                return rsaPrivateKeyStructure;
            return new RsaPrivateKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        public static RsaPrivateKeyStructure GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
            return new RsaPrivateKeyStructure(Asn1Sequence.GetInstance(obj, isExplicit));
        }

        private readonly BigInteger m_modulus;
        private readonly BigInteger m_publicExponent;
        private readonly BigInteger m_privateExponent;
        private readonly BigInteger m_prime1;
        private readonly BigInteger m_prime2;
        private readonly BigInteger m_exponent1;
        private readonly BigInteger m_exponent2;
        private readonly BigInteger m_coefficient;

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
            int count = seq.Count;
            if (count != 9)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            var version = DerInteger.GetInstance(seq[0]);
            m_modulus = DerInteger.GetInstance(seq[1]).Value;
            m_publicExponent = DerInteger.GetInstance(seq[2]).Value;
            m_privateExponent = DerInteger.GetInstance(seq[3]).Value;
            m_prime1 = DerInteger.GetInstance(seq[4]).Value;
            m_prime2 = DerInteger.GetInstance(seq[5]).Value;
            m_exponent1 = DerInteger.GetInstance(seq[6]).Value;
            m_exponent2 = DerInteger.GetInstance(seq[7]).Value;
            m_coefficient = DerInteger.GetInstance(seq[8]).Value;

            if (!version.HasValue(0))
                throw new ArgumentException("wrong version for RSA private key");
        }

        public BigInteger Modulus => m_modulus;

        public BigInteger PublicExponent => m_publicExponent;

        public BigInteger PrivateExponent => m_privateExponent;

        public BigInteger Prime1 => m_prime1;

        public BigInteger Prime2 => m_prime2;

        public BigInteger Exponent1 => m_exponent1;

        public BigInteger Exponent2 => m_exponent2;

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
