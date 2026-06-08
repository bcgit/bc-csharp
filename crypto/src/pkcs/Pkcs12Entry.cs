using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkcs
{
    /// <summary>
    /// Base class for PKCS#12 bag entries (private keys and certificates) carrying optional
    /// PKCS#9 bag attributes such as friendly name and local key identifier.
    /// </summary>
    public abstract class Pkcs12Entry
    {
        private readonly IDictionary<DerObjectIdentifier, Asn1Encodable> m_attributes;

        // TODO[api] Remove 'protected'
        protected internal Pkcs12Entry(IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
        {
            // TODO No copy, so the object is effectively sharing the dictionary (externally mutable)
            m_attributes = attributes;
        }

        /// <summary>
        /// Gets the bag attribute value for the given object identifier, or <c>null</c> if absent.
        /// </summary>
        /// <param name="oid">The bag attribute OID.</param>
        public Asn1Encodable this[DerObjectIdentifier oid] => CollectionUtilities.GetValueOrNull(m_attributes, oid);

        /// <summary>Gets the object identifiers of all bag attributes on this entry.</summary>
        public IEnumerable<DerObjectIdentifier> BagAttributeKeys => CollectionUtilities.Proxy(m_attributes.Keys);

        /// <summary>
        /// Returns <c>true</c> if this entry has a PKCS#9 friendly name attribute.
        /// </summary>
        public bool HasFriendlyName => m_attributes.ContainsKey(PkcsObjectIdentifiers.Pkcs9AtFriendlyName);

        /// <summary>
        /// Sets or replaces the PKCS#9 friendly name bag attribute on this entry.
        /// </summary>
        /// <param name="friendlyName">The friendly name to store.</param>
        public void SetFriendlyName(string friendlyName)
        {
            m_attributes[PkcsObjectIdentifiers.Pkcs9AtFriendlyName] = new DerBmpString(friendlyName);
        }

        /// <summary>
        /// Attempts to retrieve a bag attribute by OID.
        /// </summary>
        /// <param name="oid">The bag attribute OID.</param>
        /// <param name="attribute">The attribute value, if present.</param>
        /// <returns><c>true</c> if the attribute was found.</returns>
        public bool TryGetAttribute(DerObjectIdentifier oid, out Asn1Encodable attribute) =>
            m_attributes.TryGetValue(oid, out attribute);
    }
}
