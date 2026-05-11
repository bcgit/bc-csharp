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
                oid.Equals(X509Name.SerialNumber) ||
                oid.Equals(X509Name.DnQualifier) ||
                oid.Equals(X509Name.TelephoneNumber))
            {
                return new DerPrintableString(value);
            }

            return new DerUtf8String(value);
        }
    }
}
