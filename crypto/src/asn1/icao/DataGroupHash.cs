using System;

namespace Org.BouncyCastle.Asn1.Icao
{
    /**
    * The DataGroupHash object.
    * <pre>
    * DataGroupHash  ::=  SEQUENCE {
    *      dataGroupNumber         DataGroupNumber,
    *      dataGroupHashValue     OCTET STRING }
    *
    * DataGroupNumber ::= INTEGER {
    *         dataGroup1    (1),
    *         dataGroup1    (2),
    *         dataGroup1    (3),
    *         dataGroup1    (4),
    *         dataGroup1    (5),
    *         dataGroup1    (6),
    *         dataGroup1    (7),
    *         dataGroup1    (8),
    *         dataGroup1    (9),
    *         dataGroup1    (10),
    *         dataGroup1    (11),
    *         dataGroup1    (12),
    *         dataGroup1    (13),
    *         dataGroup1    (14),
    *         dataGroup1    (15),
    *         dataGroup1    (16) }
    *
    * </pre>
    */
    public class DataGroupHash
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="DataGroupHash"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="DataGroupHash"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="DataGroupHash"/>, or null if <paramref name="obj"/> is null.</returns>
        public static DataGroupHash GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DataGroupHash dataGroupHash)
                return dataGroupHash;
            return new DataGroupHash(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="DataGroupHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DataGroupHash"/>.</returns>
        public static DataGroupHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DataGroupHash(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="DataGroupHash"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="DataGroupHash"/>.</returns>
        public static DataGroupHash GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DataGroupHash(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_dataGroupNumber;
        private readonly Asn1OctetString m_dataGroupHashValue;

        private DataGroupHash(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_dataGroupNumber = Asn1Utilities.Read(seq, ref pos, DerInteger.GetInstance);
            m_dataGroupHashValue = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="DataGroupHash"/>.</summary>
        /// <param name="dataGroupNumber">The data group number.</param>
        /// <param name="dataGroupHashValue">The data group hash value.</param>
        public DataGroupHash(int dataGroupNumber, Asn1OctetString dataGroupHashValue)
        {
            m_dataGroupNumber = DerInteger.ValueOf(dataGroupNumber);
            m_dataGroupHashValue = dataGroupHashValue ?? throw new ArgumentNullException(nameof(dataGroupHashValue));
        }

        /// <summary>Gets the data group number.</summary>
        public int DataGroupNumber => m_dataGroupNumber.IntValueExact;

        /// <summary>Gets the data group hash value.</summary>
        public Asn1OctetString DataGroupHashValue => m_dataGroupHashValue;

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => new DerSequence(m_dataGroupNumber, m_dataGroupHashValue);
    }
}
