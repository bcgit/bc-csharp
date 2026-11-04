namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The CRLReason enumeration.
     * <pre>
     * CRLReason ::= Enumerated {
     *  unspecified             (0),
     *  keyCompromise           (1),
     *  cACompromise            (2),
     *  affiliationChanged      (3),
     *  superseded              (4),
     *  cessationOfOperation    (5),
     *  certificateHold         (6),
     *  removeFromCRL           (8),
     *  privilegeWithdrawn      (9),
     *  aACompromise           (10)
     * }
     * </pre>
     */
    public class CrlReason
        : DerEnumerated
    {
        /// <summary>The <c>Unspecified</c> constant, with the value <c>0</c>.</summary>
        public const int Unspecified = 0;
        /// <summary>The <c>KeyCompromise</c> constant, with the value <c>1</c>.</summary>
        public const int KeyCompromise = 1;
        /// <summary>The <c>CACompromise</c> constant, with the value <c>2</c>.</summary>
        public const int CACompromise = 2;
        /// <summary>The <c>AffiliationChanged</c> constant, with the value <c>3</c>.</summary>
        public const int AffiliationChanged = 3;
        /// <summary>The <c>Superseded</c> constant, with the value <c>4</c>.</summary>
        public const int Superseded = 4;
        /// <summary>The <c>CessationOfOperation</c> constant, with the value <c>5</c>.</summary>
        public const int CessationOfOperation = 5;
        /// <summary>The <c>CertificateHold</c> constant, with the value <c>6</c>.</summary>
        public const int CertificateHold = 6;
        /// <summary>The <c>RemoveFromCrl</c> constant, with the value <c>8</c>.</summary>
        // 7 -> Unknown
        public const int RemoveFromCrl = 8;
        /// <summary>The <c>PrivilegeWithdrawn</c> constant, with the value <c>9</c>.</summary>
        public const int PrivilegeWithdrawn = 9;
        /// <summary>The <c>AACompromise</c> constant, with the value <c>10</c>.</summary>
        public const int AACompromise = 10;

        private static readonly string[] ReasonString = new string[]
        {
            "Unspecified", "KeyCompromise", "CACompromise", "AffiliationChanged",
            "Superseded", "CessationOfOperation", "CertificateHold", "Unknown",
            "RemoveFromCrl", "PrivilegeWithdrawn", "AACompromise"
        };

        /// <summary>Create a new <see cref="CrlReason"/>.</summary>
        /// <param name="reason">The reason.</param>
        public CrlReason(int reason)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(reason)
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }

        /// <summary>Create a new <see cref="CrlReason"/>.</summary>
        /// <param name="reason">The reason.</param>
        public CrlReason(DerEnumerated reason)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(reason.IntValueExact)
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }

        /// <inheritdoc/>
        public override string ToString()
        {
            int reason = IntValueExact;
            string str = (reason < 0 || reason > 10) ? "Invalid" : ReasonString[reason];
            return "CrlReason: " + str;
        }
    }
}
