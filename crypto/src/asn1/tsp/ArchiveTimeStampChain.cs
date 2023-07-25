using System;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * Implementation of ArchiveTimeStampChain type, as defined in RFC4998 and RFC6283.
     * <p/>
     * An ArchiveTimeStampChain corresponds to a SEQUENCE OF ArchiveTimeStamps, and has the following
     * ASN.1 Syntax:
     * <p/>
     * ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
     */
    public class ArchiveTimeStampChain
        : Asn1Encodable
    {
        /**
         * Return an ArchiveTimeStampChain from the given object.
         *
         * @param obj the object we want converted.
         * @return an ArchiveTimeStampChain instance, or null.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        public static ArchiveTimeStampChain GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is ArchiveTimeStampChain archiveTimeStampChain)
                return archiveTimeStampChain;
            return new ArchiveTimeStampChain(Asn1Sequence.GetInstance(obj));
        }

        public static ArchiveTimeStampChain GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new ArchiveTimeStampChain(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly Asn1Sequence m_archiveTimeStamps;

        public ArchiveTimeStampChain(ArchiveTimeStamp archiveTimeStamp)
        {
            m_archiveTimeStamps = new DerSequence(archiveTimeStamp);
        }

        public ArchiveTimeStampChain(ArchiveTimeStamp[] archiveTimeStamps)
        {
            m_archiveTimeStamps = new DerSequence(archiveTimeStamps);
        }

        private ArchiveTimeStampChain(Asn1Sequence sequence)
        {
            Asn1EncodableVector vector = new Asn1EncodableVector(sequence.Count);

            foreach (var element in sequence)
            {
                vector.Add(ArchiveTimeStamp.GetInstance(element));
            }

            m_archiveTimeStamps = new DerSequence(vector);
        }

        public virtual ArchiveTimeStamp[] GetArchiveTimestamps() =>
            m_archiveTimeStamps.MapElements(ArchiveTimeStamp.GetInstance);

        /**
         * Adds an {@link ArchiveTimeStamp} object to the archive timestamp chain.
         *
         * @param archiveTimeStamp the {@link ArchiveTimeStamp} to add.
         * @return returns the modified chain.
         */
        public virtual ArchiveTimeStampChain Append(ArchiveTimeStamp archiveTimeStamp)
        {
            Asn1EncodableVector v = new Asn1EncodableVector(m_archiveTimeStamps.Count + 1);

            foreach (var element in m_archiveTimeStamps)
            {
                v.Add(element);
            }

            v.Add(archiveTimeStamp);

            return new ArchiveTimeStampChain(new DerSequence(v));
        }

        public override Asn1Object ToAsn1Object() => m_archiveTimeStamps;
    }
}
