using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1.X509
{
    public class NameConstraints
		: Asn1Encodable
	{
		private readonly Asn1Sequence m_permitted, m_excluded;

		public static NameConstraints GetInstance(object obj)
		{
			if (obj == null)
				return null;
			if (obj is NameConstraints nameConstraints)
				return nameConstraints;
#pragma warning disable CS0618 // Type or member is obsolete
            return new NameConstraints(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        public static NameConstraints GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return GetInstance(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        [Obsolete("Use 'GetInstance' instead")]
        public NameConstraints(Asn1Sequence seq)
		{
			foreach (Asn1TaggedObject o in seq)
			{
				switch (o.TagNo)
				{
				case 0:
					m_permitted = Asn1Sequence.GetInstance(o, false);
					break;
				case 1:
					m_excluded = Asn1Sequence.GetInstance(o, false);
					break;
				}
			}
		}

        /**
		 * Constructor from a given details.
		 *
		 * <p>permitted and excluded are Vectors of GeneralSubtree objects.</p>
		 *
		 * @param permitted Permitted subtrees
		 * @param excluded Excluded subtrees
		 */
		public NameConstraints(IList<GeneralSubtree> permitted, IList<GeneralSubtree> excluded)
		{
			if (permitted != null)
			{
				m_permitted = CreateSequence(permitted);
			}

			if (excluded != null)
			{
				m_excluded = CreateSequence(excluded);
			}
		}

		private DerSequence CreateSequence(IList<GeneralSubtree> subtrees)
		{
			Asn1EncodableVector v = new Asn1EncodableVector(subtrees.Count);
			foreach (var subtree in subtrees)
			{
				v.Add(subtree);
			}
            return new DerSequence(v);
		}

		public Asn1Sequence PermittedSubtrees => m_permitted;

		public Asn1Sequence ExcludedSubtrees => m_excluded;

		/*
		 * NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
		 * OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }
		 */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_permitted);
            v.AddOptionalTagged(false, 1, m_excluded);
            return new DerSequence(v);
        }
	}
}
