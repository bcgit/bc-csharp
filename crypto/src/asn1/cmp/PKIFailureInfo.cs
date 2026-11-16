using System;

namespace Org.BouncyCastle.Asn1.Cmp
{
    /**
     * <pre>
     * PKIFailureInfo ::= BIT STRING {
     * badAlg               (0),
     *   -- unrecognized or unsupported Algorithm Identifier
     * badMessageCheck      (1), -- integrity check failed (e.g., signature did not verify)
     * badRequest           (2),
     *   -- transaction not permitted or supported
     * badTime              (3), -- messageTime was not sufficiently close to the system time, as defined by local policy
     * badCertId            (4), -- no certificate could be found matching the provided criteria
     * badDataFormat        (5),
     *   -- the data submitted has the wrong format
     * wrongAuthority       (6), -- the authority indicated in the request is different from the one creating the response token
     * incorrectData        (7), -- the requester's data is incorrect (for notary services)
     * missingTimeStamp     (8), -- when the timestamp is missing but should be there (by policy)
     * badPOP               (9)  -- the proof-of-possession failed
     * certRevoked         (10),
     * certConfirmed       (11),
     * wrongIntegrity      (12),
     * badRecipientNonce   (13),
     * timeNotAvailable    (14),
     *   -- the TSA's time source is not available
     * unacceptedPolicy    (15),
     *   -- the requested TSA policy is not supported by the TSA
     * unacceptedExtension (16),
     *   -- the requested extension is not supported by the TSA
     * addInfoNotAvailable (17)
     *   -- the additional information requested could not be understood
     *   -- or is not available
     * badSenderNonce      (18),
     * badCertTemplate     (19),
     * signerNotTrusted    (20),
     * transactionIdInUse  (21),
     * unsupportedVersion  (22),
     * notAuthorized       (23),
     * systemUnavail       (24),
     * systemFailure       (25),
     *   -- the request cannot be handled due to system failure
     * duplicateCertReq    (26)
     * </pre>
     */
    public class PkiFailureInfo
        : DerBitString
    {
        /// <summary>The <c>BadAlg</c> failure bit: an unrecognized or unsupported algorithm identifier.</summary>
        public const int BadAlg               = (1 << 7); // unrecognized or unsupported Algorithm Identifier
        /// <summary>
        /// The <c>BadMessageCheck</c> failure bit: the integrity check failed, for example a signature did not verify.
        /// </summary>
        public const int BadMessageCheck      = (1 << 6); // integrity check failed (e.g., signature did not verify)
        /// <summary>The <c>BadRequest</c> failure bit: the transaction is not permitted or supported.</summary>
        public const int BadRequest           = (1 << 5);
        /// <summary>
        /// The <c>BadTime</c> failure bit: the message time was not sufficiently close to the system time, as defined
        /// by local policy.
        /// </summary>
        public const int BadTime              = (1 << 4); // -- messageTime was not sufficiently close to the system time, as defined by local policy
        /// <summary>
        /// The <c>BadCertId</c> failure bit: no certificate could be found matching the provided criteria.
        /// </summary>
        public const int BadCertId            = (1 << 3); // no certificate could be found matching the provided criteria
        /// <summary>The <c>BadDataFormat</c> failure bit: the data submitted has the wrong format.</summary>
        public const int BadDataFormat        = (1 << 2);
        /// <summary>
        /// The <c>WrongAuthority</c> failure bit: the authority indicated in the request is different from the one
        /// creating the response token.
        /// </summary>
        public const int WrongAuthority       = (1 << 1); // the authority indicated in the request is different from the one creating the response token
        /// <summary>The <c>IncorrectData</c> constant, with the value <c>1</c>.</summary>
        public const int IncorrectData        = 1;        // the requester's data is incorrect (for notary services)
        /// <summary>
        /// The <c>MissingTimeStamp</c> failure bit: the time stamp is missing but should be there (by policy).
        /// </summary>
        public const int MissingTimeStamp     = (1 << 15); // when the timestamp is missing but should be there (by policy)
        /// <summary>The <c>BadPop</c> failure bit: the proof-of-possession failed.</summary>
        public const int BadPop               = (1 << 14); // the proof-of-possession failed
        /// <summary>The <c>CertRevoked</c> failure bit: the certificate has already been revoked.</summary>
        public const int CertRevoked          = (1 << 13);
        /// <summary>The <c>CertConfirmed</c> failure bit: the certificate has already been confirmed.</summary>
        public const int CertConfirmed        = (1 << 12);
        /// <summary>The <c>WrongIntegrity</c> failure bit.</summary>
        public const int WrongIntegrity       = (1 << 11);
        /// <summary>The <c>BadRecipientNonce</c> failure bit.</summary>
        public const int BadRecipientNonce    = (1 << 10);
        /// <summary>The <c>TimeNotAvailable</c> failure bit: the time source of the TSA is not available.</summary>
        public const int TimeNotAvailable     = (1 << 9); // the TSA's time source is not available
        /// <summary>
        /// The <c>UnacceptedPolicy</c> failure bit: the requested TSA policy is not supported by the TSA.
        /// </summary>
        public const int UnacceptedPolicy     = (1 << 8); // the requested TSA policy is not supported by the TSA
        /// <summary>
        /// The <c>UnacceptedExtension</c> failure bit: the requested extension is not supported by the TSA.
        /// </summary>
        public const int UnacceptedExtension  = (1 << 23); //the requested extension is not supported by the TSA
        /// <summary>
        /// The <c>AddInfoNotAvailable</c> failure bit: the additional information requested could not be understood or
        /// is not available.
        /// </summary>
        public const int AddInfoNotAvailable  = (1 << 22); //the additional information requested could not be understood or is not available
        /// <summary>The <c>BadSenderNonce</c> failure bit.</summary>
        public const int BadSenderNonce       = (1 << 21);
        /// <summary>The <c>BadCertTemplate</c> failure bit.</summary>
        public const int BadCertTemplate      = (1 << 20);
        /// <summary>The <c>SignerNotTrusted</c> failure bit.</summary>
        public const int SignerNotTrusted     = (1 << 19);
        /// <summary>The <c>TransactionIdInUse</c> failure bit.</summary>
        public const int TransactionIdInUse   = (1 << 18);
        /// <summary>The <c>UnsupportedVersion</c> failure bit.</summary>
        public const int UnsupportedVersion   = (1 << 17);
        /// <summary>The <c>NotAuthorized</c> failure bit.</summary>
        public const int NotAuthorized        = (1 << 16);
        /// <summary>The <c>SystemUnavail</c> failure bit.</summary>
        public const int SystemUnavail        = (1 << 31);
        /// <summary>
        /// The <c>SystemFailure</c> failure bit: the request cannot be handled due to system failure.
        /// </summary>
        public const int SystemFailure        = (1 << 30); //the request cannot be handled due to system failure
        /// <summary>The <c>DuplicateCertReq</c> failure bit.</summary>
        public const int DuplicateCertReq     = (1 << 29);

        /**
         * Basic constructor.
         */
        public PkiFailureInfo(int info)
            : base(info)
        {
        }

        /// <summary>Create a new <see cref="PkiFailureInfo"/>.</summary>
        /// <param name="info">The info.</param>
        public PkiFailureInfo(
            DerBitString info)
            : base(info.GetBytes(), info.PadBits)
        {
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            return "PkiFailureInfo: 0x" + this.IntValue.ToString("X");
        }
    }
}
