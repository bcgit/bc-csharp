namespace Org.BouncyCastle.Asn1.Ocsp
{
    /// <summary>The values of the OCSPResponseStatus type of RFC 6960.</summary>
    public class OcspResponseStatus
        : DerEnumerated
    {
        /// <summary>The <c>Successful</c> constant, with the value <c>0</c>.</summary>
        public const int Successful = 0;
        /// <summary>The <c>MalformedRequest</c> constant, with the value <c>1</c>.</summary>
        public const int MalformedRequest = 1;
        /// <summary>The <c>InternalError</c> constant, with the value <c>2</c>.</summary>
        public const int InternalError = 2;
        /// <summary>The <c>TryLater</c> constant, with the value <c>3</c>.</summary>
        public const int TryLater = 3;
        /// <summary>The <c>SignatureRequired</c> constant, with the value <c>5</c>.</summary>
        public const int SignatureRequired = 5;
        /// <summary>The <c>Unauthorized</c> constant, with the value <c>6</c>.</summary>
        public const int Unauthorized = 6;

        /**
         * The OcspResponseStatus enumeration.
         * <pre>
         * OcspResponseStatus ::= Enumerated {
         *     successful            (0),  --Response has valid confirmations
         *     malformedRequest      (1),  --Illegal confirmation request
         *     internalError         (2),  --Internal error in issuer
         *     tryLater              (3),  --Try again later
         *                                 --(4) is not used
         *     sigRequired           (5),  --Must sign the request
         *     unauthorized          (6)   --Request unauthorized
         * }
         * </pre>
         */
        public OcspResponseStatus(int value)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(value)
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }

        /// <summary>Create a new <see cref="OcspResponseStatus"/>.</summary>
        /// <param name="value">The value.</param>
        public OcspResponseStatus(DerEnumerated value)
#pragma warning disable CS0618 // Type or member is obsolete
            : base(value.IntValueExact)
#pragma warning restore CS0618 // Type or member is obsolete
        {
        }
    }
}
