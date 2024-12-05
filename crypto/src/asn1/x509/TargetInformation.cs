namespace Org.BouncyCastle.Asn1.X509
{
    /**
	 * Target information extension for attributes certificates according to RFC
	 * 3281.
	 * 
	 * <pre>
	 *           SEQUENCE OF Targets
	 * </pre>
	 * 
	 */
    public class TargetInformation
		: Asn1Encodable
	{
        /**
		 * Creates an instance of a TargetInformation from the given object.
		 * <p>
		 * <code>obj</code> can be a TargetInformation or a {@link Asn1Sequence}</p>
		 * 
		 * @param obj The object.
		 * @return A TargetInformation instance.
		 * @throws ArgumentException if the given object cannot be interpreted as TargetInformation.
		 */
        public static TargetInformation GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is TargetInformation targetInformation)
                return targetInformation;
            return new TargetInformation(Asn1Sequence.GetInstance(obj));
        }

        public static TargetInformation GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TargetInformation(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static TargetInformation GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new TargetInformation(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_targets;

        /**
		 * Constructor from a Asn1Sequence.
		 * 
		 * @param seq The Asn1Sequence.
		 * @throws ArgumentException if the sequence does not contain
		 *             correctly encoded Targets elements.
		 */
        private TargetInformation(Asn1Sequence targets)
        {
            m_targets = targets;
        }

        /**
		 * Returns the targets in this target information extension.
		 * <p>
		 * The ArrayList is cloned before it is returned.</p>
		 * 
		 * @return Returns the targets.
		 */
        public virtual Targets[] GetTargetsObjects() => m_targets.MapElements(Targets.GetInstance);

        /**
		 * Constructs a target information from a single targets element. 
		 * According to RFC 3281 only one targets element must be produced.
		 * 
		 * @param targets A Targets instance.
		 */
        public TargetInformation(Targets targets)
		{
			m_targets = new DerSequence(targets);
		}

		/**
		 * According to RFC 3281 only one targets element must be produced. If
		 * multiple targets are given they must be merged in
		 * into one targets element.
		 *
		 * @param targets An array with {@link Targets}.
		 */
		public TargetInformation(Target[] targets)
			: this(new Targets(targets))
		{
		}

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 * 
		 * Returns:
		 * 
		 * <pre>
		 *          SEQUENCE OF Targets
		 * </pre>
		 * 
		 * <p>
		 * According to RFC 3281 only one targets element must be produced. If
		 * multiple targets are given in the constructor they are merged into one
		 * targets element. If this was produced from a
		 * {@link Org.BouncyCastle.Asn1.Asn1Sequence} the encoding is kept.</p>
		 * 
		 * @return an Asn1Object
		 */
		public override Asn1Object ToAsn1Object() => m_targets;
	}
}
