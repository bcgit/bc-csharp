using System;

namespace Org.BouncyCastle.Asn1.CryptoPro
{
    /// <summary>The parameters of the GOST 28147-89 cipher: an initialization vector and a parameter set.</summary>
    public class Gost28147Parameters
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="Gost28147Parameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="Gost28147Parameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="Gost28147Parameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Gost28147Parameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Gost28147Parameters gost28147Parameters)
                return gost28147Parameters;
            return new Gost28147Parameters(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Gost28147Parameters"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Gost28147Parameters"/>.</returns>
        public static Gost28147Parameters GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new Gost28147Parameters(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="Gost28147Parameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Gost28147Parameters"/>.</returns>
        public static Gost28147Parameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Gost28147Parameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1OctetString m_iv;
        private readonly DerObjectIdentifier m_encryptionParamSet;

        private Gost28147Parameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            // TODO Validate length of 8?
            m_iv = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);
            m_encryptionParamSet = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Gost28147Parameters"/>.</summary>
        /// <param name="iv">The initialization vector.</param>
        /// <param name="encryptionParamSet">The encryption param set.</param>
        public Gost28147Parameters(Asn1OctetString iv, DerObjectIdentifier encryptionParamSet)
        {
            m_iv = iv ?? throw new ArgumentNullException(nameof(iv));
            m_encryptionParamSet = encryptionParamSet ?? throw new ArgumentNullException(nameof(encryptionParamSet));
        }

        /// <summary>Gets the IV.</summary>
        public Asn1OctetString IV => m_iv;

        /// <summary>Gets the encryption param set.</summary>
        public DerObjectIdentifier EncryptionParamSet => m_encryptionParamSet;

        /**
         * <pre>
         * Gost28147-89-Parameters ::=
         *               SEQUENCE {
         *                       iv                   Gost28147-89-IV,
         *                       encryptionParamSet   OBJECT IDENTIFIER
         *                }
         *
         *   Gost28147-89-IV ::= OCTET STRING (SIZE (8))
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_iv, m_encryptionParamSet);
    }
}
