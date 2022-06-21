using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.X509
{
	public interface IX509Extension
	{
		/// <summary>
		/// Get all critical extension values, by oid
		/// </summary>
		/// <returns>IDictionary with string (OID) keys and Asn1OctetString values</returns>
		ISet GetCriticalExtensionOids();

		/// <summary>
		/// Get all non-critical extension values, by oid
		/// </summary>
		/// <returns>IDictionary with string (OID) keys and Asn1OctetString values</returns>
		ISet GetNonCriticalExtensionOids();

		Asn1OctetString GetExtensionValue(DerObjectIdentifier oid);
	}
}
