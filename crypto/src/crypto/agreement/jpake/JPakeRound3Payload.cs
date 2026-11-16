using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Agreement.JPake
{
    /// <summary>
    /// The payload sent/received during the optional third round of a J-PAKE exchange,
    /// which is for explicit key confirmation.
    ///
    /// Each JPAKEParticipant creates and sends an instance
    /// of this payload to the other JPAKEParticipant.
    /// The payload to send should be created via
    /// JPAKEParticipant#createRound3PayloadToSend(BigInteger)
    ///
    /// Eeach JPAKEParticipant must also validate the payload
    /// received from the other JPAKEParticipant.
    /// The received payload should be validated via
    /// JPAKEParticipant#validateRound3PayloadReceived(JPakeRound3Payload, BigInteger)
    /// </summary>
    public class JPakeRound3Payload
    {
        /// <summary>
        /// The id of the {@link JPAKEParticipant} who created/sent this payload.
        /// </summary>
        private readonly string participantId;

        /// <summary>
        /// The value of MacTag, as computed by round 3.
        ///
        /// See JPAKEUtil#calculateMacTag(string, string, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, Org.BouncyCastle.Crypto.Digest)
        /// </summary>
        private readonly BigInteger macTag;

        /// <summary>Create a new <see cref="JPakeRound3Payload"/>.</summary>
        /// <param name="participantId">The participant id.</param>
        /// <param name="magTag">The mag tag.</param>
        public JPakeRound3Payload(string participantId, BigInteger magTag)
        {
            this.participantId = participantId;
            this.macTag = magTag;
        }

        /// <summary>Gets the participant id.</summary>
        public virtual string ParticipantId => participantId;

        /// <summary>Gets the mac tag.</summary>
        public virtual BigInteger MacTag => macTag;
    }
}
