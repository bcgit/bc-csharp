using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Agreement.JPake
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
    /// JPAKEParticipant.ValidateRound1PayloadReceived(JPakeRound1Payload).
    /// </summary>
    public class JPakeRound1Payload
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

        /// <summary>Create a new <see cref="JPakeRound1Payload"/>.</summary>
        /// <param name="participantId">The participant id.</param>
        /// <param name="gx1">The gx 1.</param>
        /// <param name="gx2">The gx 2.</param>
        /// <param name="knowledgeProofForX1">The knowledge proof for x 1.</param>
        /// <param name="knowledgeProofForX2">The knowledge proof for x 2.</param>
        public JPakeRound1Payload(string participantId, BigInteger gx1, BigInteger gx2,
            BigInteger[] knowledgeProofForX1, BigInteger[] knowledgeProofForX2)
        {
            JPakeUtilities.ValidateNotNull(participantId, "participantId");
            JPakeUtilities.ValidateNotNull(gx1, "gx1");
            JPakeUtilities.ValidateNotNull(gx2, "gx2");
            JPakeUtilities.ValidateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
            JPakeUtilities.ValidateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

            this.participantId = participantId;
            this.gx1 = gx1;
            this.gx2 = gx2;
            this.knowledgeProofForX1 = Copy(knowledgeProofForX1);
            this.knowledgeProofForX2 = Copy(knowledgeProofForX2);
        }

        /// <summary>Gets the participant id.</summary>
        public virtual string ParticipantId => participantId;

        /// <summary>Gets the gx 1.</summary>
        public virtual BigInteger Gx1 => gx1;

        /// <summary>Gets the gx 2.</summary>
        public virtual BigInteger Gx2 => gx2;

        /// <summary>Gets the knowledge proof for x 1.</summary>
        public virtual BigInteger[] KnowledgeProofForX1 => Copy(knowledgeProofForX1);

        /// <summary>Gets the knowledge proof for x 2.</summary>
        public virtual BigInteger[] KnowledgeProofForX2 => Copy(knowledgeProofForX2);

        private static BigInteger[] Copy(BigInteger[] bis) => Arrays.CopyOf(bis, bis.Length);
    }
}
