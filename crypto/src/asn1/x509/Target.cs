using System;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Target structure used in target information extension for attribute
     * certificates from RFC 3281.
     * 
     * <pre>
     *     Target  ::= CHOICE {
     *       targetName          [0] GeneralName,
     *       targetGroup         [1] GeneralName,
     *       targetCert          [2] TargetCert
     *     }
     * </pre>
     * 
     * <p>
     * The targetCert field is currently not supported and must not be used
     * according to RFC 3281.</p>
     */
    public class Target
        : Asn1Encodable, IAsn1Choice
    {
        public enum Choice
        {
            Name = 0,
            Group = 1
        };

        /**
         * Creates an instance of a Target from the given object.
         * <p>
         * <code>obj</code> can be a Target or a {@link Asn1TaggedObject}</p>
         * 
         * @param obj The object.
         * @return A Target instance.
         * @throws ArgumentException if the given object cannot be
         *             interpreted as Target.
         */
        public static Target GetInstance(object obj) => Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static Target GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetInstanceChoice(taggedObject, declaredExplicit, GetInstance);

        public static Target GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Target target)
                return target;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                if (taggedObject.HasContextTag((int)Choice.Name) ||
                    taggedObject.HasContextTag((int)Choice.Group))
                {
                    return new Target(taggedObject);
                }
            }

            return null;
        }

        public static Target GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private readonly GeneralName m_targetName;
        private readonly GeneralName m_targetGroup;

        /**
         * Constructor from Asn1TaggedObject.
         * 
         * @param tagObj The tagged object.
         * @throws ArgumentException if the encoding is wrong.
         */
        private Target(Asn1TaggedObject tagObj)
        {
            Debug.Assert(tagObj.HasContextTag());

            // GeneralName is a CHOICE so must be explicitly tagged
            switch (tagObj.TagNo)
            {
            case (int)Choice.Name:
                m_targetName = GeneralName.GetInstance(tagObj, true);
                break;
            case (int)Choice.Group:
                m_targetGroup = GeneralName.GetInstance(tagObj, true);
                break;
            default:
                throw new ArgumentException("unknown tag: " + tagObj.TagNo);
            }
        }

        /**
         * Constructor from given details.
         * <p>
         * Exactly one of the parameters must be not <code>null</code>.</p>
         *
         * @param type the choice type to apply to the name.
         * @param name the general name.
         * @throws ArgumentException if type is invalid.
         */
        public Target(Choice type, GeneralName name)
            : this(new DerTaggedObject((int)type, name))
        {
        }

        /**
         * @return Returns the targetGroup.
         */
        public virtual GeneralName TargetGroup => m_targetGroup;

        /**
         * @return Returns the targetName.
         */
        public virtual GeneralName TargetName => m_targetName;

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * 
         * Returns:
         * 
         * <pre>
         *     Target  ::= CHOICE {
         *       targetName          [0] GeneralName,
         *       targetGroup         [1] GeneralName,
         *       targetCert          [2] TargetCert
         *     }
         * </pre>
         * 
         * @return an Asn1Object
         */
        public override Asn1Object ToAsn1Object()
        {
            // GeneralName is a CHOICE so must be explicitly tagged
            if (m_targetName != null)
                return new DerTaggedObject(true, 0, m_targetName);
            if (m_targetGroup != null)
                return new DerTaggedObject(true, 1, m_targetGroup);
            throw new InvalidOperationException();
        }
    }
}
