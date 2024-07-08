using System;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Asn1.Icao
{
    /**
	 * The LDSSecurityObject object (V1.8).
	 * <pre>
	 * LDSSecurityObject ::= SEQUENCE {
	 *   version                LDSSecurityObjectVersion,
	 *   hashAlgorithm          DigestAlgorithmIdentifier,
	 *   dataGroupHashValues    SEQUENCE SIZE (2..ub-DataGroups) OF DataHashGroup,
	 *   ldsVersionInfo         LDSVersionInfo OPTIONAL
	 *     -- if present, version MUST be v1 }
	 *
	 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier,
	 *
	 * LDSSecurityObjectVersion :: INTEGER {V0(0)}
	 * </pre>
	 */
    public class LdsSecurityObject
		: Asn1Encodable
	{
		public const int UBDataGroups = 16;

        public static LdsSecurityObject GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is LdsSecurityObject ldsSecurityObject)
                return ldsSecurityObject;
            return new LdsSecurityObject(Asn1Sequence.GetInstance(obj));
        }

        public static LdsSecurityObject GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LdsSecurityObject(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static LdsSecurityObject GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LdsSecurityObject(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

		private readonly DerInteger m_version;
        private readonly AlgorithmIdentifier m_hashAlgorithm;
        private readonly DataGroupHash[] m_datagroupHashValues;
        private readonly LdsVersionInfo m_ldsVersionInfo;

        private LdsSecurityObject(Asn1Sequence seq)
		{
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 4)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_version = DerInteger.GetInstance(seq[pos++]);
			m_hashAlgorithm = AlgorithmIdentifier.GetInstance(seq[pos++]);
			m_datagroupHashValues = ConvertDataGroupHash(Asn1Sequence.GetInstance(seq[pos++]));
			m_ldsVersionInfo = Asn1Utilities.ReadOptional(seq, ref pos, LdsVersionInfo.GetOptional);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

			if (m_ldsVersionInfo != null && !m_version.HasValue(1))
				throw new ArgumentException("'ldsVersionInfo' is present, but 'version' is NOT 'v1'");
        }

        public LdsSecurityObject(AlgorithmIdentifier digestAlgorithmIdentifier, DataGroupHash[] datagroupHash)
        {
            m_version = DerInteger.Zero;
			m_hashAlgorithm = digestAlgorithmIdentifier ?? throw new ArgumentNullException(nameof(digestAlgorithmIdentifier)); ;
			m_datagroupHashValues = datagroupHash ?? throw new ArgumentNullException(nameof(datagroupHash));
            m_ldsVersionInfo = null;

			CheckDatagroupHashCount(m_datagroupHashValues.Length);
		}

        public LdsSecurityObject(AlgorithmIdentifier digestAlgorithmIdentifier, DataGroupHash[] datagroupHash,
            LdsVersionInfo versionInfo)
        {
            m_version = DerInteger.One;
            m_hashAlgorithm = digestAlgorithmIdentifier ?? throw new ArgumentNullException(nameof(digestAlgorithmIdentifier)); ;
            m_datagroupHashValues = datagroupHash ?? throw new ArgumentNullException(nameof(datagroupHash));
            m_ldsVersionInfo = versionInfo;

            CheckDatagroupHashCount(m_datagroupHashValues.Length);
        }

        public BigInteger Version => m_version.Value;

		public AlgorithmIdentifier DigestAlgorithmIdentifier => m_hashAlgorithm;

		public DataGroupHash[] GetDatagroupHash() => m_datagroupHashValues;

		public LdsVersionInfo VersionInfo => m_ldsVersionInfo;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(4);
            v.Add(m_version, m_hashAlgorithm, DerSequence.FromElements(m_datagroupHashValues));
            v.AddOptional(m_ldsVersionInfo);
            return new DerSequence(v);
        }

        private static void CheckDatagroupHashCount(int count)
        {
            if (count < 2 || count > UBDataGroups)
                throw new ArgumentException("wrong size in DataGroupHashValues : not in (2.." + UBDataGroups + ")");
        }

		private static DataGroupHash[] ConvertDataGroupHash(Asn1Sequence seq)
		{
            CheckDatagroupHashCount(seq.Count);

			return seq.MapElements(DataGroupHash.GetInstance);
		}
    }
}
