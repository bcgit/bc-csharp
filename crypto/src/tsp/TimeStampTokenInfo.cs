using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Tsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Tsp
{
    /// <summary>The TSTInfo content of an RFC 3161 time-stamp token.</summary>
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

        /// <summary>Parse from the encoding of a TSTInfo structure.</summary>
        /// <param name="tstInfoEncoding">The encoded TSTInfo.</param>
        /// <exception cref="TspException">The encoding or its genTime field cannot be parsed.</exception>
        public TimeStampTokenInfo(byte[] tstInfoEncoding)
            : this(ParseTstInfo(tstInfoEncoding))
        {
        }

        /// <summary>Create from an ASN.1 TstInfo structure.</summary>
        /// <param name="tstInfo">The ASN.1 structure.</param>
        /// <exception cref="ArgumentNullException"><paramref name="tstInfo"/> is null.</exception>
        /// <exception cref="TspException">The genTime field cannot be parsed.</exception>
        public TimeStampTokenInfo(TstInfo tstInfo)
        {
            m_tstInfo = tstInfo ?? throw new ArgumentNullException(nameof(tstInfo));

            try
            {
                m_genTime = tstInfo.GenTime.ToDateTime();
            }
            catch (Exception e)
            {
                throw new TspException("unable to parse genTime field: " + e.Message);
            }
        }

        /// <summary>Gets whether time-stamp tokens issued by the TSA can be ordered by their genTime alone.</summary>
        public bool IsOrdered => m_tstInfo.Ordering.IsTrue;

        /// <summary>Gets the accuracy of genTime, or null if the token does not state one.</summary>
        public Accuracy Accuracy => m_tstInfo.Accuracy;

        /// <summary>Gets the time at which the time-stamp token was created by the TSA.</summary>
        public DateTime GenTime => m_genTime;

        /// <summary>Gets the accuracy of genTime in a convenient form, or null if none is stated.</summary>
        public GenTimeAccuracy GenTimeAccuracy => Accuracy == null ? null : new GenTimeAccuracy(Accuracy);

        /// <summary>Gets the object identifier of the TSA policy under which the token was issued.</summary>
        public string Policy => m_tstInfo.Policy.GetID();

        /// <summary>Gets the serial number of the token, unique among those issued by the TSA.</summary>
        public BigInteger SerialNumber => m_tstInfo.SerialNumber.Value;

        /// <summary>Gets the name of the TSA, or null if not present.</summary>
        public GeneralName Tsa => m_tstInfo.Tsa;

        /// <summary>Gets the nonce echoed from the request, or null if the request had none.</summary>
        public BigInteger Nonce => m_tstInfo.Nonce?.Value;

        /// <summary>Gets the message imprint (hash algorithm and digest) that was time-stamped.</summary>
        public MessageImprint MessageImprint => m_tstInfo.MessageImprint;

        /// <summary>Gets the hash algorithm of the message imprint.</summary>
        public AlgorithmIdentifier HashAlgorithm => MessageImprint.HashAlgorithm;

        /// <summary>Gets the message imprint alg oid.</summary>
        [Obsolete("Will be removed")]
        public string MessageImprintAlgOid => HashAlgorithm.Algorithm.GetID();

        /// <summary>Gets the digest of the message imprint.</summary>
        public Asn1OctetString MessageImprintDigest => MessageImprint.HashedMessage;

        /// <summary>Return the digest of the message imprint.</summary>
        public byte[] GetMessageImprintDigest() => MessageImprint.GetHashedMessage();

        /// <summary>Return the ASN.1 encoded representation of this object.</summary>
        public byte[] GetEncoded() => m_tstInfo.GetEncoded();

        /// <summary>Return the underlying ASN.1 structure.</summary>
        public TstInfo TstInfo => m_tstInfo;
    }
}
