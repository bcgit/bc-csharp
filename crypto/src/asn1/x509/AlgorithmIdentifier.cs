using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The AlgorithmIdentifier structure of RFC 5280: an algorithm and its optional parameters.</summary>
    public class AlgorithmIdentifier
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AlgorithmIdentifier"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AlgorithmIdentifier"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AlgorithmIdentifier"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AlgorithmIdentifier GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AlgorithmIdentifier algorithmIdentifier)
                return algorithmIdentifier;
            return new AlgorithmIdentifier(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AlgorithmIdentifier"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AlgorithmIdentifier"/>.</returns>
        public static AlgorithmIdentifier GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new AlgorithmIdentifier(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="AlgorithmIdentifier"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="AlgorithmIdentifier"/>, or null if <paramref name="element"/> is null.</returns>
        public static AlgorithmIdentifier GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is AlgorithmIdentifier algorithmIdentifier)
                return algorithmIdentifier;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new AlgorithmIdentifier(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="AlgorithmIdentifier"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AlgorithmIdentifier"/>.</returns>
        public static AlgorithmIdentifier GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AlgorithmIdentifier(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_algorithm;
        private readonly Asn1Encodable m_parameters;

        internal AlgorithmIdentifier(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algorithm = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            // TODO[asn1] Asn1Utilities helper method for this type of situation
            m_parameters = Asn1Utilities.ReadOptional(seq, ref pos, element => element);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="AlgorithmIdentifier"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        public AlgorithmIdentifier(DerObjectIdentifier algorithm)
            : this(algorithm, null)
        {
        }

        /// <summary>Create a new <see cref="AlgorithmIdentifier"/>.</summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="parameters">The parameters.</param>
        public AlgorithmIdentifier(DerObjectIdentifier algorithm, Asn1Encodable parameters)
        {
            m_algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            m_parameters = parameters;
        }

        /// <summary>
        /// Return the OID in the Algorithm entry of this identifier.
        /// </summary>
        public virtual DerObjectIdentifier Algorithm => m_algorithm;

        /// <summary>
        /// Return the parameters structure in the Parameters entry of this identifier.
        /// </summary>
        public virtual Asn1Encodable Parameters => m_parameters;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         *      AlgorithmIdentifier ::= Sequence {
         *                            algorithm OBJECT IDENTIFIER,
         *                            parameters ANY DEFINED BY algorithm OPTIONAL }
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            return m_parameters == null
                ?  new DerSequence(m_algorithm)
                :  new DerSequence(m_algorithm, m_parameters);
        }
    }
}
