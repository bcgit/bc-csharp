using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The DigestInfo object.
     * <pre>
     * DigestInfo::=Sequence{
     *          digestAlgorithm  AlgorithmIdentifier,
     *          digest OCTET STRING }
     * </pre>
     */
    public class DigestInfo
        : Asn1Encodable
    {
		public static DigestInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DigestInfo digestInfo)
                return digestInfo;
            return new DigestInfo(Asn1Sequence.GetInstance(obj));
		}

        public static DigestInfo GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new DigestInfo(Asn1Sequence.GetInstance(obj, explicitly));

        public static DigestInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DigestInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_digestAlgorithm;
        private readonly Asn1OctetString m_digest;

        private DigestInfo(Asn1Sequence seq)
        {
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_digestAlgorithm = AlgorithmIdentifier.GetInstance(seq[0]);
            m_digest = Asn1OctetString.GetInstance(seq[1]);
        }

        public DigestInfo(AlgorithmIdentifier algID, byte[] digest)
        {
            m_digestAlgorithm = algID ?? throw new ArgumentNullException(nameof(algID));
            m_digest = new DerOctetString(digest);
        }

        public AlgorithmIdentifier AlgorithmID => m_digestAlgorithm;

        public AlgorithmIdentifier DigestAlgorithm => m_digestAlgorithm;

        public Asn1OctetString Digest => m_digest;

        public byte[] GetDigest() => m_digest.GetOctets();

		public override Asn1Object ToAsn1Object() => new DerSequence(m_digestAlgorithm, m_digest);
    }
}
