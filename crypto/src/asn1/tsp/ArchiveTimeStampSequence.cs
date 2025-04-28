using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of ArchiveTimeStampSequence type, as defined in RFC4998.
     * <p/>
     * An ArchiveTimeStampSequence corresponds to a SEQUENCE OF ArchiveTimeStampChains and has the
     * following ASN.1 Syntax:
     * <p/>
     * ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
     */
    public class ArchiveTimeStampSequence
        : Asn1Encodable
    {
        /**
         * Return an ArchiveTimestampSequence from the given object.
         *
         * @param obj the object we want converted.
         * @return an ArchiveTimeStampSequence instance, or null.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        public static ArchiveTimeStampSequence GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ArchiveTimeStampSequence archiveTimeStampSequence)
                return archiveTimeStampSequence;
            return new ArchiveTimeStampSequence(Asn1Sequence.GetInstance(obj));
        }

        public static ArchiveTimeStampSequence GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ArchiveTimeStampSequence(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static ArchiveTimeStampSequence GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new ArchiveTimeStampSequence(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly Asn1Sequence m_archiveTimeStampChains;

        private ArchiveTimeStampSequence(Asn1Sequence seq)
        {
            m_archiveTimeStampChains = DerSequence.Map(seq, ArchiveTimeStampChain.GetInstance);
        }

        public ArchiveTimeStampSequence(ArchiveTimeStampChain archiveTimeStampChain)
        {
            m_archiveTimeStampChains = new DerSequence(archiveTimeStampChain);
        }

        public ArchiveTimeStampSequence(ArchiveTimeStampChain[] archiveTimeStampChains)
        {
            m_archiveTimeStampChains = DerSequence.FromElements(archiveTimeStampChains);
        }

        /**
         * Returns the sequence of ArchiveTimeStamp chains that compose the ArchiveTimeStamp sequence.
         *
         * @return the {@link ASN1Sequence} containing the ArchiveTimeStamp chains.
         */
        public virtual ArchiveTimeStampChain[] GetArchiveTimeStampChains() =>
            m_archiveTimeStampChains.MapElements(ArchiveTimeStampChain.GetInstance);

        public virtual int Count => m_archiveTimeStampChains.Count;

        /**
         * Adds an {@link ArchiveTimeStampChain} to the ArchiveTimeStamp sequence.
         *
         * @param chain the {@link ArchiveTimeStampChain} to add
         * @return returns the modified sequence.
         */
        public virtual ArchiveTimeStampSequence Append(ArchiveTimeStampChain chain)
        {
            if (chain == null)
                throw new ArgumentNullException(nameof(chain));

            Asn1EncodableVector v = new Asn1EncodableVector(m_archiveTimeStampChains.Count + 1);
            v.AddAll(m_archiveTimeStampChains);
            v.Add(chain);

            return new ArchiveTimeStampSequence(new DerSequence(v));
        }

        public override Asn1Object ToAsn1Object() => m_archiveTimeStampChains;
    }
}
