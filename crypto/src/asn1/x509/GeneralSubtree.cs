using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
	 * Class for containing a restriction object subtrees in NameConstraints. See
	 * RFC 3280.
	 *
	 * <pre>
	 *
	 *       GeneralSubtree ::= SEQUENCE
	 *       {
	 *         baseName                    GeneralName,
	 *         minimum         [0]     BaseDistance DEFAULT 0,
	 *         maximum         [1]     BaseDistance OPTIONAL
	 *       }
	 * </pre>
	 *
	 * @see org.bouncycastle.asn1.x509.NameConstraints
	 *
	 */
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
            : this(baseName, null, null)
        {
        }

        /**
		 * Constructor from a given details.
		 *
		 * According RFC 3280, the minimum and maximum fields are not used with any
		 * name forms, thus minimum MUST be zero, and maximum MUST be absent.
		 * <p>
		 * If minimum is <code>null</code>, zero is assumed, if
		 * maximum is <code>null</code>, maximum is absent.</p>
		 *
		 * @param baseName
		 *            A restriction.
		 * @param minimum
		 *            Minimum
		 *
		 * @param maximum
		 *            Maximum
		 */
        public GeneralSubtree(GeneralName baseName, BigInteger minimum, BigInteger maximum)
        {
            m_baseName = baseName ?? throw new ArgumentNullException(nameof(baseName));
			m_minimum = minimum == null ? DerInteger.Zero : new DerInteger(minimum);
			m_maximum = maximum == null ? null : new DerInteger(maximum);
        }

		public GeneralName Base => m_baseName;

		public BigInteger Minimum => m_minimum.Value;

		public BigInteger Maximum => m_maximum?.Value;

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 *
		 * Returns:
		 *
		 * <pre>
		 *       GeneralSubtree ::= SEQUENCE
		 *       {
		 *         baseName                    GeneralName,
		 *         minimum         [0]     BaseDistance DEFAULT 0,
		 *         maximum         [1]     BaseDistance OPTIONAL
		 *       }
		 * </pre>
		 *
		 * @return a DERObject
		 */
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
