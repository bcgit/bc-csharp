using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.X509
{
    /// <summary>Interface for objects, such as certificates and CRLs, that carry X.509 extensions.</summary>
    public interface IX509Extension
    {
        /// <summary>
        /// Get all critical extension values, by oid
        /// </summary>
        /// <returns>IDictionary with string (OID) keys and Asn1OctetString values</returns>
        ISet<string> GetCriticalExtensionOids();

        /// <summary>
        /// Get all non-critical extension values, by oid
        /// </summary>
        /// <returns>IDictionary with string (OID) keys and Asn1OctetString values</returns>
        ISet<string> GetNonCriticalExtensionOids();

        /// <summary>Get the value of an extension.</summary>
        /// <param name="oid">The object identifier of the extension.</param>
        /// <returns>The DER encoded value of the extension, or null if it is not present.</returns>
        Asn1OctetString GetExtensionValue(DerObjectIdentifier oid);
    }
}
