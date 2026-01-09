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

        private readonly DigestInfo m_mac;
        private readonly Asn1OctetString m_macSalt;
        private readonly DerInteger m_iterations;

        private MacData(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_mac = DigestInfo.GetInstance(seq[pos++]);
            m_macSalt = Asn1OctetString.GetInstance(seq[pos++]);
            m_iterations = Asn1Utilities.ReadOptional(seq, ref pos, DerInteger.GetOptional) ?? DerInteger.One;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        // TODO[api] Fix parameter names
        public MacData(DigestInfo digInfo, byte[] salt, int iterationCount)
        {
            m_mac = digInfo ?? throw new ArgumentNullException(nameof(digInfo));
            m_macSalt = DerOctetString.FromContents(salt);
            m_iterations = DerInteger.ValueOf(iterationCount);
        }

        public MacData(DigestInfo mac, Asn1OctetString macSalt, DerInteger iterations)
        {
            m_mac = mac ?? throw new ArgumentNullException(nameof(mac));
            m_macSalt = macSalt ?? throw new ArgumentNullException(nameof(macSalt));
            m_iterations = iterations ?? throw new ArgumentNullException(nameof(iterations));
        }

        public DigestInfo Mac => m_mac;

        public byte[] GetSalt() => (byte[])m_macSalt.GetOctets().Clone();

        public BigInteger IterationCount => m_iterations.Value;

        public DerInteger Iterations => m_iterations;

        public Asn1OctetString MacSalt => m_macSalt;

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
            return m_iterations.HasValue(1)
                ?  new DerSequence(m_mac, m_macSalt)
                :  new DerSequence(m_mac, m_macSalt, m_iterations);
        }
    }
}
