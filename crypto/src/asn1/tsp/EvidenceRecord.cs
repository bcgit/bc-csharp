using System;

using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Tsp
{
    /**
     * <a href="https://tools.ietf.org/html/rfc4998">RFC 4998</a>:
     * Evidence Record Syntax (ERS)
     * <p/>
     * <pre>
     * EvidenceRecord ::= SEQUENCE {
     *   version                   INTEGER { v1(1) } ,
     *   digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
     *   cryptoInfos               [0] CryptoInfos OPTIONAL,
     *   encryptionInfo            [1] EncryptionInfo OPTIONAL,
     *   archiveTimeStampSequence  ArchiveTimeStampSequence
     * }
     *
     * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
     * </pre>
     */
    public class EvidenceRecord
        : Asn1Encodable
    {
        /**
         * ERS {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ltans(11)
         * id-mod(0) id-mod-ers88(2) id-mod-ers88-v1(1) }
         */
        private static readonly DerObjectIdentifier Oid = new DerObjectIdentifier("1.3.6.1.5.5.11.0.2.1");

        /**
         * Return an EvidenceRecord from the given object.
         *
         * @param obj the object we want converted.
         * @return an EvidenceRecord instance, or null.
         * @throws IllegalArgumentException if the object cannot be converted.
         */
        public static EvidenceRecord GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is EvidenceRecord evidenceRecord)
                return evidenceRecord;
            return new EvidenceRecord(Asn1Sequence.GetInstance(obj));
        }

        public static EvidenceRecord GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EvidenceRecord(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static EvidenceRecord GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new EvidenceRecord(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerInteger m_version;
        private readonly Asn1Sequence m_digestAlgorithms;
        private readonly CryptoInfos m_cryptoInfos;
        private readonly EncryptionInfo m_encryptionInfo;
        private readonly ArchiveTimeStampSequence m_archiveTimeStampSequence;

        private EvidenceRecord(EvidenceRecord evidenceRecord, ArchiveTimeStampSequence replacementSequence,
            ArchiveTimeStamp newChainTimeStamp)
        {
            m_version = evidenceRecord.m_version;

            // check the list of digest algorithms is correct.
            if (newChainTimeStamp != null)
            {
                AlgorithmIdentifier algID = newChainTimeStamp.GetDigestAlgorithmIdentifier();
                Asn1EncodableVector vector = new Asn1EncodableVector();

                bool found = false;

                foreach (var element in evidenceRecord.m_digestAlgorithms)
                {
                    AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.GetInstance(element);
                    vector.Add(algorithmIdentifier);

                    if (algorithmIdentifier.Equals(algID))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    vector.Add(algID);
                    m_digestAlgorithms = new DerSequence(vector);
                }
                else
                {
                    m_digestAlgorithms = evidenceRecord.m_digestAlgorithms;
                }
            }
            else
            {
                m_digestAlgorithms = evidenceRecord.m_digestAlgorithms;
            }

            m_cryptoInfos = evidenceRecord.m_cryptoInfos;
            m_encryptionInfo = evidenceRecord.m_encryptionInfo;
            m_archiveTimeStampSequence = replacementSequence;
        }

        /**
         * Build a basic evidence record from an initial
         * ArchiveTimeStamp.
         * 
         * @param cryptoInfos
         * @param encryptionInfo
         * @param archiveTimeStamp
         */
        public EvidenceRecord(CryptoInfos cryptoInfos, EncryptionInfo encryptionInfo, ArchiveTimeStamp archiveTimeStamp)
        {
            m_version = DerInteger.One;
            m_digestAlgorithms = new DerSequence(archiveTimeStamp.GetDigestAlgorithmIdentifier());
            m_cryptoInfos = cryptoInfos;
            m_encryptionInfo = encryptionInfo;
            m_archiveTimeStampSequence = new ArchiveTimeStampSequence(new ArchiveTimeStampChain(archiveTimeStamp));
        }

        public EvidenceRecord(AlgorithmIdentifier[] digestAlgorithms, CryptoInfos cryptoInfos,
            EncryptionInfo encryptionInfo, ArchiveTimeStampSequence archiveTimeStampSequence)
        {
            m_version = DerInteger.One;
            m_digestAlgorithms = new DerSequence(digestAlgorithms);
            m_cryptoInfos = cryptoInfos;
            m_encryptionInfo = encryptionInfo;
            m_archiveTimeStampSequence = archiveTimeStampSequence;
        }

        private EvidenceRecord(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 3 || count > 5)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_version = DerInteger.GetInstance(seq[pos++]);
            m_digestAlgorithms = Asn1Sequence.GetInstance(seq[pos++]);
            m_cryptoInfos = Asn1Utilities.ReadContextTagged(seq, ref pos, 0, false, CryptoInfos.GetTagged);
            m_encryptionInfo = Asn1Utilities.ReadContextTagged(seq, ref pos, 1, false, EncryptionInfo.GetTagged);
            m_archiveTimeStampSequence = ArchiveTimeStampSequence.GetInstance(seq[pos++]);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            if (!m_version.HasValue(1))
                throw new ArgumentException("incompatible version");
        }

        public virtual DerInteger Version => m_version;

        public virtual AlgorithmIdentifier[] GetDigestAlgorithms() =>
            m_digestAlgorithms.MapElements(AlgorithmIdentifier.GetInstance);

        public virtual CryptoInfos CryptoInfos => m_cryptoInfos;

        public virtual EncryptionInfo EncryptionInfo => m_encryptionInfo;

        public virtual ArchiveTimeStampSequence ArchiveTimeStampSequence => m_archiveTimeStampSequence;

        /**
         * Return a new EvidenceRecord with an added ArchiveTimeStamp
         *
         * @param ats         the archive timestamp to add
         * @param newChain states whether this new archive timestamp must be added as part of a
         *                    new sequence (i.e. in the case of hashtree renewal) or not (i.e. in the case of timestamp
         *                    renewal)
         * @return the new EvidenceRecord
         */
        public virtual EvidenceRecord AddArchiveTimeStamp(ArchiveTimeStamp ats, bool newChain)
        {
            if (newChain)
            {
                ArchiveTimeStampChain chain = new ArchiveTimeStampChain(ats);

                return new EvidenceRecord(this, m_archiveTimeStampSequence.Append(chain), ats);
            }
            else
            {
                ArchiveTimeStampChain[] chains = m_archiveTimeStampSequence.GetArchiveTimeStampChains();

                AlgorithmIdentifier digAlg = chains[chains.Length - 1].GetArchiveTimestamps()[0]
                    .GetDigestAlgorithmIdentifier();
                if (!digAlg.Equals(ats.GetDigestAlgorithmIdentifier()))
                    throw new ArgumentException("mismatch of digest algorithm in AddArchiveTimeStamp");

                chains[chains.Length - 1] = chains[chains.Length - 1].Append(ats);
                return new EvidenceRecord(this, new ArchiveTimeStampSequence(chains), null);
            }
        }

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector vector = new Asn1EncodableVector(5);
            vector.Add(m_version, m_digestAlgorithms);
            vector.AddOptionalTagged(false, 0, m_cryptoInfos);
            vector.AddOptionalTagged(false, 1, m_encryptionInfo);
            vector.Add(m_archiveTimeStampSequence);
            return new DerSequence(vector);
        }
    }
}
