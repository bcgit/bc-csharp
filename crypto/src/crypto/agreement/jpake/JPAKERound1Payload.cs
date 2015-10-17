using System;

using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Agreement.Jpake
{
    /// <summary>
    /// The payload sent/received during the first round of a J-PAKE exchange.
    /// 
    /// Each JPAKEParticipant creates and sends an instance of this payload to
    /// the other. The payload to send should be created via 
    /// JPAKEParticipant.CreateRound1PayloadToSend().
    /// 
    /// Each participant must also validate the payload received from the other.
    /// The received payload should be validated via 
    /// JPAKEParticipant.ValidateRound1PayloadReceived(JPAKERound1Payload).
    /// </summary>
    public class JPAKERound1Payload
    {
        /// <summary>
        /// The id of the JPAKEParticipant who created/sent this payload.
        /// </summary>
        private readonly string participantId;

        /// <summary>
        /// The value of g^x1
        /// </summary>
        private readonly BigInteger gx1;

        /// <summary>
        /// The value of g^x2
        /// </summary>
        private readonly BigInteger gx2;

        /// <summary>
        /// The zero knowledge proof for x1.
        /// 
        /// This is a two element array, containing {g^v, r} for x1.
        /// </summary>
        private readonly BigInteger[] knowledgeProofForX1;

        /// <summary>
        /// The zero knowledge proof for x2.
        /// 
        /// This is a two element array, containing {g^v, r} for x2.
        /// </summary>
        private readonly BigInteger[] knowledgeProofForX2;

        public JPAKERound1Payload(string participantId, BigInteger gx1, BigInteger gx2, BigInteger[] knowledgeProofForX1, BigInteger[] knowledgeProofForX2)
        {
            JPAKEUtil.ValidateNotNull(participantId, "participantId");
            JPAKEUtil.ValidateNotNull(gx1, "gx1");
            JPAKEUtil.ValidateNotNull(gx2, "gx2");
            JPAKEUtil.ValidateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
            JPAKEUtil.ValidateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

            this.participantId = participantId;
            this.gx1 = gx1;
            this.gx2 = gx2;
            this.knowledgeProofForX1 = new BigInteger[knowledgeProofForX1.Length];
            Array.Copy(knowledgeProofForX1, this.knowledgeProofForX1, knowledgeProofForX1.Length);
            this.knowledgeProofForX2 = new BigInteger[knowledgeProofForX2.Length];
            Array.Copy(knowledgeProofForX2, this.knowledgeProofForX2, knowledgeProofForX2.Length);
        }

        public string ParticipantId
        {
            get { return participantId; }
        }

        public BigInteger Gx1
        {
            get { return gx1; }
        }

        public BigInteger Gx2
        {
            get { return gx2; }
        }

        public BigInteger[] KnowledgeProofForX1
        {
            get
            {
                BigInteger[] kp = new BigInteger[knowledgeProofForX1.Length];
                Array.Copy(knowledgeProofForX1, kp, knowledgeProofForX1.Length);
                return kp;
            }
        }

        public BigInteger[] KnowledgeProofForX2
        {
            get
            {
                BigInteger[] kp = new BigInteger[knowledgeProofForX2.Length];
                Array.Copy(knowledgeProofForX2, kp, knowledgeProofForX2.Length);
                return kp;
            }
        }
    }
}
