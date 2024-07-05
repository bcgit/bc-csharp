namespace Org.BouncyCastle.Asn1.X509
{
    /**
	 * Targets structure used in target information extension for attribute
	 * certificates from RFC 3281.
	 * 
	 * <pre>
	 *            Targets ::= SEQUENCE OF Target
	 *           
	 *            Target  ::= CHOICE {
	 *              targetName          [0] GeneralName,
	 *              targetGroup         [1] GeneralName,
	 *              targetCert          [2] TargetCert
	 *            }
	 *           
	 *            TargetCert  ::= SEQUENCE {
	 *              targetCertificate    IssuerSerial,
	 *              targetName           GeneralName OPTIONAL,
	 *              certDigestInfo       ObjectDigestInfo OPTIONAL
	 *            }
	 * </pre>
	 * 
	 * @see org.bouncycastle.asn1.x509.Target
	 * @see org.bouncycastle.asn1.x509.TargetInformation
	 */
    public class Targets
		: Asn1Encodable
	{
        /**
		 * Creates an instance of a Targets from the given object.
		 * <p>
		 * <code>obj</code> can be a Targets or a {@link Asn1Sequence}</p>
		 * 
		 * @param obj The object.
		 * @return A Targets instance.
		 * @throws ArgumentException if the given object cannot be interpreted as Target.
		 */
        public static Targets GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Targets targets)
                return targets;
            return new Targets(Asn1Sequence.GetInstance(obj));
        }

        public static Targets GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Targets(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static Targets GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Targets(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_targets;

        /**
		 * Constructor from Asn1Sequence.
		 * 
		 * @param targets The ASN.1 SEQUENCE.
		 * @throws ArgumentException if the contents of the sequence are
		 *             invalid.
		 */
        private Targets(Asn1Sequence targets)
        {
            m_targets = targets;
        }

        /**
		 * Constructor from given targets.
		 * <p>
		 * The ArrayList is copied.</p>
		 * 
		 * @param targets An <code>ArrayList</code> of {@link Target}s.
		 * @see Target
		 * @throws ArgumentException if the ArrayList contains not only Targets.
		 */
        public Targets(Target[] targets)
        {
            m_targets = DerSequence.FromElements(targets);
        }

        /**
		 * Returns the targets in an <code>ArrayList</code>.
		 * <p>
		 * The ArrayList is cloned before it is returned.</p>
		 * 
		 * @return Returns the targets.
		 */
        public virtual Target[] GetTargets() => m_targets.MapElements(Target.GetInstance);

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 * 
		 * Returns:
		 * 
		 * <pre>
		 *            Targets ::= SEQUENCE OF Target
		 * </pre>
		 * 
		 * @return an Asn1Object
		 */
		public override Asn1Object ToAsn1Object() => m_targets;
	}
}
