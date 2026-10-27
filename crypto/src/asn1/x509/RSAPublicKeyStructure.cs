using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The RSAPublicKey structure of PKCS#1.</summary>
    public class RsaPublicKeyStructure
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="RsaPublicKeyStructure"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="RsaPublicKeyStructure"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="RsaPublicKeyStructure"/>, or null if <paramref name="obj"/> is null.</returns>
        public static RsaPublicKeyStructure GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RsaPublicKeyStructure rsaPublicKeyStructure)
                return rsaPublicKeyStructure;
            return new RsaPublicKeyStructure(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="RsaPublicKeyStructure"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsaPublicKeyStructure"/>.</returns>
        public static RsaPublicKeyStructure GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new RsaPublicKeyStructure(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="RsaPublicKeyStructure"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="RsaPublicKeyStructure"/>.</returns>
        public static RsaPublicKeyStructure GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RsaPublicKeyStructure(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly BigInteger m_modulus;
        private readonly BigInteger m_publicExponent;

        private RsaPublicKeyStructure(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // Note: we are accepting technically incorrect (i.e. negative) values here
            m_modulus = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).PositiveValue;
            m_publicExponent = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance).PositiveValue;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="RsaPublicKeyStructure"/>.</summary>
        /// <param name="modulus">The modulus.</param>
        /// <param name="publicExponent">The public exponent.</param>
        public RsaPublicKeyStructure(BigInteger modulus, BigInteger publicExponent)
        {
            if (modulus == null)
                throw new ArgumentNullException("modulus");
            if (publicExponent == null)
                throw new ArgumentNullException("publicExponent");
            if (modulus.SignValue <= 0)
                throw new ArgumentException("Not a valid RSA modulus", "modulus");
            if (publicExponent.SignValue <= 0)
                throw new ArgumentException("Not a valid RSA public exponent", "publicExponent");

            m_modulus = modulus;
            m_publicExponent = publicExponent;
        }

        /// <summary>Gets the modulus.</summary>
        public BigInteger Modulus => m_modulus;

        /// <summary>Gets the public exponent.</summary>
        public BigInteger PublicExponent => m_publicExponent;

        /**
         * This outputs the key in Pkcs1v2 format.
         * <pre>
         *      RSAPublicKey ::= Sequence {
         *                          modulus Integer, -- n
         *                          publicExponent Integer, -- e
         *                      }
         * </pre>
         */
        public override Asn1Object ToAsn1Object() =>
            new DerSequence(new DerInteger(m_modulus), new DerInteger(m_publicExponent));
    }
}
