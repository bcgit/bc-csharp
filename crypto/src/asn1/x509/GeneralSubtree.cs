using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>
    /// Class for containing a restriction object subtrees in NameConstraints. See RFC 3280.
    /// </summary>
    /// <remarks>
    /// <code>
    /// GeneralSubtree ::= SEQUENCE
    /// {
    ///     base            GeneralName,
    ///     minimum     [0] BaseDistance DEFAULT 0,
    ///     maximum     [1] BaseDistance OPTIONAL
    /// }
    /// </code>
    /// </remarks>
    public class GeneralSubtree
        : Asn1Encodable
    {
        public static GeneralSubtree GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GeneralSubtree generalSubtree)
                return generalSubtree;
            return new GeneralSubtree(Asn1Sequence.GetInstance(obj));
        }

        public static GeneralSubtree GetInstance(Asn1TaggedObject o, bool isExplicit) =>
            new GeneralSubtree(Asn1Sequence.GetInstance(o, isExplicit));

        public static GeneralSubtree GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GeneralSubtree(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralName m_baseName;
        private readonly DerInteger m_minimum;
        private readonly DerInteger m_maximum;

        private GeneralSubtree(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_baseName = GeneralName.GetInstance(seq[pos++]);
            m_minimum = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, DerInteger.GetTagged)
                ?? DerInteger.Zero;
            m_maximum = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerInteger.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public GeneralSubtree(GeneralName baseName)
            : this(baseName, (DerInteger)null, (DerInteger)null)
        {
        }

        /// <summary>Constructor from the given details.</summary>
        /// <remarks>
        /// According to RFC 3280, the minimum and maximum fields are not used with any name forms, thus minimum MUST
        /// be zero, and maximum MUST be absent. If minimum is <c>null</c>, zero is assumed, if maximum is <c>null</c>,
        /// maximum is absent.
        /// </remarks>
        /// <param name="baseName"/>
        /// <param name="minimum"/>
        /// <param name="maximum"/>
        [Obsolete("Use version taking 'DerInteger' values instead")]
        public GeneralSubtree(GeneralName baseName, BigInteger minimum, BigInteger maximum)
        {
            m_baseName = baseName ?? throw new ArgumentNullException(nameof(baseName));
            m_minimum = minimum == null ? DerInteger.Zero : new DerInteger(minimum);
            m_maximum = maximum == null ? null : new DerInteger(maximum);
        }

        /// <summary>Constructor from the given details.</summary>
        /// <remarks>
        /// According to RFC 3280, the minimum and maximum fields are not used with any name forms, thus minimum MUST
        /// be zero, and maximum MUST be absent. If minimum is <c>null</c>, zero is assumed, if maximum is <c>null</c>,
        /// maximum is absent.
        /// </remarks>
        /// <param name="baseName"/>
        /// <param name="minimum"/>
        /// <param name="maximum"/>
        public GeneralSubtree(GeneralName baseName, DerInteger minimum, DerInteger maximum)
        {
            m_baseName = baseName ?? throw new ArgumentNullException(nameof(baseName));
            m_minimum = minimum ?? DerInteger.Zero;
            m_maximum = maximum;
        }

        public GeneralName Base => m_baseName;

        // TODO[api] Eventually use this property for the actual DerInteger
        [Obsolete("Use 'MinimumObect.Value' instead")]
        public BigInteger Minimum => m_minimum.Value;

        public DerInteger MinimumObject => m_minimum;

        // TODO[api] Eventually use this proeprty for the actual DerInteger
        [Obsolete("Use 'MaximumObect?.Value' instead")]
        public BigInteger Maximum => m_maximum?.Value;

        public DerInteger MaximumObject => m_maximum;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.Add(m_baseName);

            if (!m_minimum.HasValue(0))
            {
                v.Add(new DerTaggedObject(false, 0, m_minimum));
            }

            v.AddOptionalTagged(false, 1, m_maximum);
            return new DerSequence(v);
        }
    }
}
