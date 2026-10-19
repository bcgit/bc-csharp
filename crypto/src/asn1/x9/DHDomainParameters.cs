using System;

namespace Org.BouncyCastle.Asn1.X9
{
    /// <summary>The DomainParameters structure of ANSI X9.42 for Diffie-Hellman.</summary>
    [Obsolete("Use 'DomainParameters' instead")]
    public class DHDomainParameters
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DHDomainParameters"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DHDomainParameters"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DHDomainParameters"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DHDomainParameters GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DHDomainParameters dhDomainParameters)
                return dhDomainParameters;
            return new DHDomainParameters(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DHDomainParameters"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DHDomainParameters"/>.</returns>
        public static DHDomainParameters GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new DHDomainParameters(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="DHDomainParameters"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DHDomainParameters"/>.</returns>
        public static DHDomainParameters GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DHDomainParameters(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_p, m_g, m_q, m_j;
        private readonly ValidationParams m_validationParams;

        private DHDomainParameters(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_p = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_g = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_q = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_j = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional);
            m_validationParams = Asn1Utilities.ReadOptional(seq, ref pos, ValidationParams.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="DHDomainParameters"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="g">The g.</param>
        /// <param name="q">The q.</param>
        /// <param name="j">The j.</param>
        /// <param name="validationParms">The validation parms.</param>
        [Obsolete("Use constructor taking 'ValidationParams' instead")]
        public DHDomainParameters(DerInteger p, DerInteger g, DerInteger q, DerInteger j,
            DHValidationParms validationParms)
        {
            m_p = p ?? throw new ArgumentNullException(nameof(p));
            m_g = g ?? throw new ArgumentNullException(nameof(g));
            m_q = q ?? throw new ArgumentNullException(nameof(q));
            m_j = j;
            m_validationParams = validationParms == null
                ? null
                : new ValidationParams(validationParms.Seed, validationParms.PgenCounter);
        }

        /// <summary>Create a new <see cref="DHDomainParameters"/>.</summary>
        /// <param name="p">The p.</param>
        /// <param name="g">The g.</param>
        /// <param name="q">The q.</param>
        /// <param name="j">The j.</param>
        /// <param name="validationParams">The validation params.</param>
        public DHDomainParameters(DerInteger p, DerInteger g, DerInteger q, DerInteger j,
            ValidationParams validationParams)
        {
            m_p = p ?? throw new ArgumentNullException(nameof(p));
            m_g = g ?? throw new ArgumentNullException(nameof(g));
            m_q = q ?? throw new ArgumentNullException(nameof(q));
            m_j = j;
            m_validationParams = validationParams;
        }

        /// <summary>Gets the p.</summary>
        public DerInteger P => m_p;

        /// <summary>Gets the g.</summary>
        public DerInteger G => m_g;

        /// <summary>Gets the q.</summary>
        public DerInteger Q => m_q;

        /// <summary>Gets the j.</summary>
        public DerInteger J => m_j;

        /// <summary>Gets the validation parms.</summary>
        [Obsolete("Use 'ValidationParams' instead")]
        public DHValidationParms ValidationParms =>
            new DHValidationParms(m_validationParams.Seed, m_validationParams.PgenCounter);

        public ValidationParams ValidationParams => m_validationParams;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(5);
            v.Add(m_p, m_g, m_q);
            v.AddOptional(m_j, m_validationParams);
            return new DerSequence(v);
        }
    }
}
