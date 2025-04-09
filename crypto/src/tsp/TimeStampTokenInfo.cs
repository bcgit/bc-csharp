using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Tsp
{
    public class TimeStampTokenInfo
    {
        private static TstInfo ParseTstInfo(byte[] tstInfoEncoding)
        {
            try
            {
                return TstInfo.GetInstance(tstInfoEncoding);
            }
            catch (Exception e)
            {
                throw new TspException("unable to parse TstInfo encoding: " + e.Message);
            }
        }

        private readonly TstInfo m_tstInfo;
        private readonly DateTime m_genTime;

        public TimeStampTokenInfo(byte[] tstInfoEncoding)
            : this(ParseTstInfo(tstInfoEncoding))
        {
        }

        public TimeStampTokenInfo(TstInfo tstInfo)
        {
            m_tstInfo = tstInfo;

            try
            {
                m_genTime = tstInfo.GenTime.ToDateTime();
            }
            catch (Exception e)
            {
                throw new TspException("unable to parse genTime field: " + e.Message);
            }
        }

        public bool IsOrdered => m_tstInfo.Ordering.IsTrue;

        public Accuracy Accuracy => m_tstInfo.Accuracy;

        public DateTime GenTime => m_genTime;

        public GenTimeAccuracy GenTimeAccuracy => Accuracy == null ? null : new GenTimeAccuracy(Accuracy);

        public string Policy => m_tstInfo.Policy.GetID();

        public BigInteger SerialNumber => m_tstInfo.SerialNumber.Value;

        public GeneralName Tsa => m_tstInfo.Tsa;

        public BigInteger Nonce => m_tstInfo.Nonce?.Value;

        public AlgorithmIdentifier HashAlgorithm => m_tstInfo.MessageImprint.HashAlgorithm;

        public string MessageImprintAlgOid => m_tstInfo.MessageImprint.HashAlgorithm.Algorithm.GetID();

        public Asn1OctetString MessageImprintDigest => m_tstInfo.MessageImprint.HashedMessage;

        public byte[] GetMessageImprintDigest() => m_tstInfo.MessageImprint.GetHashedMessage();

        public byte[] GetEncoded() => m_tstInfo.GetEncoded();

        public TstInfo TstInfo => m_tstInfo;
    }
}
