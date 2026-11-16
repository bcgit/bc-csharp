using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     *  KemBMParameter ::= SEQUENCE {
     *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
     *      len              INTEGER (1..MAX),
     *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
     *   }
     * </pre>
     */
    public class KemBMParameter
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="KemBMParameter"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="KemBMParameter"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="KemBMParameter"/>, or null if <paramref name="obj"/> is null.</returns>
        public static KemBMParameter GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is KemBMParameter kemBMParameter)
                return kemBMParameter;
            return new KemBMParameter(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="KemBMParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KemBMParameter"/>.</returns>
        public static KemBMParameter GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemBMParameter(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="KemBMParameter"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="KemBMParameter"/>.</returns>
        public static KemBMParameter GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new KemBMParameter(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_kdf;
        private readonly DerInteger m_len;
        private readonly AlgorithmIdentifier m_mac;

        private KemBMParameter(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_kdf = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_len = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_mac = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="KemBMParameter"/>.</summary>
        /// <param name="kdf">The kdf.</param>
        /// <param name="len">The number of bytes.</param>
        /// <param name="mac">The MAC.</param>
        public KemBMParameter(AlgorithmIdentifier kdf, DerInteger len, AlgorithmIdentifier mac)
        {
            m_kdf = kdf ?? throw new ArgumentNullException(nameof(kdf));
            m_len = len ?? throw new ArgumentNullException(nameof(len));
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
        }

        /// <summary>Create a new <see cref="KemBMParameter"/>.</summary>
        /// <param name="kdf">The kdf.</param>
        /// <param name="len">The number of bytes.</param>
        /// <param name="mac">The MAC.</param>
        public KemBMParameter(AlgorithmIdentifier kdf, long len, AlgorithmIdentifier mac)
            : this(kdf, DerInteger.ValueOf(len), mac)
        {
        }

        /// <summary>Gets the kdf.</summary>
        public virtual AlgorithmIdentifier Kdf => m_kdf;

        /// <summary>Gets the len.</summary>
        public virtual DerInteger Len => m_len;

        /// <summary>Gets the mac.</summary>
        public virtual AlgorithmIdentifier Mac => m_mac;

        /**
         * <pre>
         *  KemBMParameter ::= SEQUENCE {
         *      kdf              AlgorithmIdentifier{KEY-DERIVATION, {...}},
         *      len              INTEGER (1..MAX),
         *      mac              AlgorithmIdentifier{MAC-ALGORITHM, {...}}
         *    }
         * </pre>
         *
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_kdf, m_len, m_mac);
    }
}
