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
        public static DataGroupHash GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DataGroupHash dataGroupHash)
                return dataGroupHash;
            return new DataGroupHash(Asn1Sequence.GetInstance(obj));
        }

        public static DataGroupHash GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return new DataGroupHash(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));
        }

        private readonly DerInteger m_dataGroupNumber;
        private readonly Asn1OctetString m_dataGroupHashValue;

        private DataGroupHash(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_dataGroupNumber = DerInteger.GetInstance(seq[0]);
            m_dataGroupHashValue = Asn1OctetString.GetInstance(seq[1]);
        }

		public DataGroupHash(int dataGroupNumber, Asn1OctetString dataGroupHashValue)
        {
            m_dataGroupNumber = new DerInteger(dataGroupNumber);
            m_dataGroupHashValue = dataGroupHashValue ?? throw new ArgumentNullException(nameof(dataGroupHashValue));
        }

		public int DataGroupNumber => m_dataGroupNumber.IntValueExact;

		public Asn1OctetString DataGroupHashValue => m_dataGroupHashValue;

		public override Asn1Object ToAsn1Object() => new DerSequence(m_dataGroupNumber, m_dataGroupHashValue);
    }
}
