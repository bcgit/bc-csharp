using System;
using System.IO;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>
    /// The default converter for X509 DN entries when going from their string value to ASN.1 strings.
    /// </summary>
    public class X509DefaultEntryConverter
        : X509NameEntryConverter
    {
        /// <summary>
        /// Apply default conversion for the given value depending on the oid and the character range of the value.
        /// </summary>
        /// <param name="oid">The object identifier for the DN entry.</param>
        /// <param name="value">The value associated with it.</param>
        /// <returns>The ASN.1 equivalent for the string value.</returns>
        public override Asn1Object GetConvertedValue(DerObjectIdentifier oid, string value)
        {
            if (value.Length != 0 && value[0] == '#')
            {
                try
                {
                    return ConvertHexEncoded(value, 1);
                }
                catch (IOException)
                {
                    throw new Exception("can't recode value for oid " + oid.Id);
                }
            }

            if (value.Length != 0 && value[0] == '\\')
            {
                value = value.Substring(1);
            }

            if (oid.Equals(X509Name.EmailAddress) || oid.Equals(X509Name.DC))
            {
                return new DerIA5String(value);
            }

            if (oid.Equals(X509Name.DateOfBirth)) // accept time string as well as # (for compatibility)
            {
                return new Asn1GeneralizedTime(value);
            }

            if (oid.Equals(X509Name.C) ||
                oid.Equals(X509Name.JurisdictionC))
            {
                if (value.Length != 2)
                {
                    // RFC 5280 sec. 4.1.2.4 / X.520: countryName is PrintableString (SIZE (2)). CAB Forum Baseline
                    // Requirements 7.1.4.2.1 narrows this to a valid ISO 3166-1 alpha-2 code. Reject
                    // obvious-wrong-length input at build time rather than encode a non-spec value that
                    // will be rejected downstream (github bc-java #2011).
                    throw new ArgumentException(
                        $"country code attribute {oid} must be exactly 2 characters per ISO 3166-1 / X.520, got {value.Length}: '{value}'");
                }

                return new DerPrintableString(value);
            }

            if (oid.Equals(X509Name.SerialNumber) ||
                oid.Equals(X509Name.DnQualifier) ||
                oid.Equals(X509Name.TelephoneNumber))
            {
                return new DerPrintableString(value);
            }

            if (oid.Equals(X509Name.CN) && value.Length > 64)
            {
                // RFC 5280 sec. A.1 / X.520: commonName is DirectoryString { ub-common-name } with ub-common-name = 64.
                // OpenSSL and most validators reject longer values, so reject at build time rather than emit a cert
                // that won't verify downstream. Existing DER-encoded names with longer CNs still parse because the
                // parse path does not route through this method (githubbc-java #750).
                throw new ArgumentException(
                    $"commonName length {value.Length} exceeds RFC 5280 ub-common-name (64): '{value}'");
            }

            return new DerUtf8String(value);
        }
    }
}
