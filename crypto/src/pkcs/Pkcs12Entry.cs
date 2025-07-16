using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkcs
{
    public abstract class Pkcs12Entry
    {
        private readonly IDictionary<DerObjectIdentifier, Asn1Encodable> m_attributes;

        // TODO[api] Remove 'protected'
        protected internal Pkcs12Entry(IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
        {
            // TODO No copy, so the object is effectively sharing the dictionary (externally mutable)
            m_attributes = attributes;
        }

        public Asn1Encodable this[DerObjectIdentifier oid] => CollectionUtilities.GetValueOrNull(m_attributes, oid);

        public IEnumerable<DerObjectIdentifier> BagAttributeKeys => CollectionUtilities.Proxy(m_attributes.Keys);

        public bool HasFriendlyName => m_attributes.ContainsKey(PkcsObjectIdentifiers.Pkcs9AtFriendlyName);

        public void SetFriendlyName(string friendlyName)
        {
            m_attributes[PkcsObjectIdentifiers.Pkcs9AtFriendlyName] = new DerBmpString(friendlyName);
        }

        public bool TryGetAttribute(DerObjectIdentifier oid, out Asn1Encodable attribute) =>
            m_attributes.TryGetValue(oid, out attribute);
    }
}
