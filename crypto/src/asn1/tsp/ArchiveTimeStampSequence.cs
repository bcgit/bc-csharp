using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of ArchiveTimeStampSequence type, as defined in RFC4998.
     * <p>
     * An ArchiveTimeStampSequence corresponds to a SEQUENCE OF ArchiveTimeStampChains and has the
     * following ASN.1 Syntax:
     * <p>
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

        public static ArchiveTimeStampSequence GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ArchiveTimeStampSequence(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_archiveTimeStampChains;

        private ArchiveTimeStampSequence(Asn1Sequence sequence)
        {
            Asn1EncodableVector vector = new Asn1EncodableVector(sequence.Count);

            foreach (var element in sequence)
            {
                vector.Add(ArchiveTimeStampChain.GetInstance(element));
            }

            m_archiveTimeStampChains = new DerSequence(vector);
        }

        public ArchiveTimeStampSequence(ArchiveTimeStampChain archiveTimeStampChain)
        {
            m_archiveTimeStampChains = new DerSequence(archiveTimeStampChain);
        }

        public ArchiveTimeStampSequence(ArchiveTimeStampChain[] archiveTimeStampChains)
        {
            m_archiveTimeStampChains = new DerSequence(archiveTimeStampChains);
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
            Asn1EncodableVector v = new Asn1EncodableVector(m_archiveTimeStampChains.Count + 1);

            foreach (var element in m_archiveTimeStampChains)
            {
                v.Add(element);
            }

            v.Add(chain);

            return new ArchiveTimeStampSequence(new DerSequence(v));
        }

        public override Asn1Object ToAsn1Object() => m_archiveTimeStampChains;
    }
}
