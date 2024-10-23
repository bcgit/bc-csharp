using System;

namespace Org.BouncyCastle.Asn1.Crmf
{
    internal class Rfc4211Asn1Utilities
    {
        internal static OptionalValidity CheckValidityFieldPresent(OptionalValidity validity)
        {
            // RFC 4211 5: If validity is not omitted, then at least one of the sub-fields MUST be specified.
            if (validity != null &&
                validity.NotBefore == null &&
                validity.NotAfter == null)
            {
                throw new ArgumentException("At least one of the sub-fields MUST be specified", nameof(validity));
            }

            return validity;
        }
    }
}
