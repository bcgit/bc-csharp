using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The AccessDescription object.
     * <pre>
     * AccessDescription  ::=  SEQUENCE {
     *       accessMethod          OBJECT IDENTIFIER,
     *       accessLocation        GeneralName  }
     * </pre>
     */
    public class AccessDescription
        : Asn1Encodable
    {
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.2</c>.</summary>
        public readonly static DerObjectIdentifier IdADCAIssuers = X509ObjectIdentifiers.IdADCAIssuers;
        /// <summary>The object identifier <c>1.3.6.1.5.5.7.48.1</c>.</summary>
        public readonly static DerObjectIdentifier IdADOcsp = X509ObjectIdentifiers.IdADOcsp;

        /// <summary>Return an <see cref="AccessDescription"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AccessDescription"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AccessDescription"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AccessDescription GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AccessDescription accessDescription)
                return accessDescription;
            return new AccessDescription(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AccessDescription"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AccessDescription"/>.</returns>
        public static AccessDescription GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AccessDescription(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AccessDescription"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AccessDescription"/>.</returns>
        public static AccessDescription GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AccessDescription(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_accessMethod;
        private readonly GeneralName m_accessLocation;

        private AccessDescription(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_accessMethod = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_accessLocation = Asn1Utilities.Read(seq, ref pos, GeneralName.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * create an AccessDescription with the oid and location provided.
         */
        // TODO[api] Change parameter names
        public AccessDescription(DerObjectIdentifier oid, GeneralName location)
        {
            m_accessMethod = oid ?? throw new ArgumentNullException(nameof(oid));
            m_accessLocation = location ?? throw new ArgumentNullException(nameof(location));
        }

        /// <summary>Gets the access method.</summary>
        public DerObjectIdentifier AccessMethod => m_accessMethod;

        /// <summary>Gets the access location.</summary>
        public GeneralName AccessLocation => m_accessLocation;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_accessMethod, m_accessLocation);

        /// <inheritdoc/>
        public override string ToString() => "AccessDescription: Oid(" + m_accessMethod.Id + ")";
    }
}
