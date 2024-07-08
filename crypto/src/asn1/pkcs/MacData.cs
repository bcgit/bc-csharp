using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Pkcs
{
    public class MacData
        : Asn1Encodable
    {
        public static MacData GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is MacData macData)
                return macData;
            return new MacData(Asn1Sequence.GetInstance(obj));
        }

        public static MacData GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MacData(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static MacData GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new MacData(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DigestInfo m_digInfo;
        private readonly Asn1OctetString m_salt;
        private readonly DerInteger m_iterationCount;

        private MacData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digInfo = DigestInfo.GetInstance(seq[pos++]);
            m_salt = Asn1OctetString.GetInstance(seq[pos++]);
            m_iterationCount = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional) ?? DerInteger.One;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public MacData(DigestInfo digInfo, byte[] salt, int iterationCount)
        {
            m_digInfo = digInfo ?? throw new ArgumentNullException(nameof(digInfo));
            m_salt = DerOctetString.FromContents(salt);
            m_iterationCount = new DerInteger(iterationCount);
        }

        public DigestInfo Mac => m_digInfo;

        public byte[] GetSalt() => (byte[])m_salt.GetOctets().Clone();

        public BigInteger IterationCount => m_iterationCount.Value;

		/**
		 * <pre>
		 * MacData ::= SEQUENCE {
		 *     mac      DigestInfo,
		 *     macSalt  OCTET STRING,
		 *     iterations INTEGER DEFAULT 1
		 *     -- Note: The default is for historic reasons and its use is deprecated. A
		 *     -- higher value, like 1024 is recommended.
		 * </pre>
		 * @return the basic DERObject construction.
		 */
		public override Asn1Object ToAsn1Object()
        {
            return m_iterationCount.HasValue(1)
                ?  new DerSequence(m_digInfo, m_salt)
                :  new DerSequence(m_digInfo, m_salt, m_iterationCount);
        }
    }
}
