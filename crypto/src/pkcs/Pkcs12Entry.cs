using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Pkcs
{
    public abstract class Pkcs12Entry
    {
		private readonly IDictionary<DerObjectIdentifier, Asn1Encodable> m_attributes;

		protected internal Pkcs12Entry(IDictionary<DerObjectIdentifier, Asn1Encodable> attributes)
        {
            m_attributes = attributes;
        }

		public Asn1Encodable this[DerObjectIdentifier oid]
		{
			get { return CollectionUtilities.GetValueOrNull(m_attributes, oid); }
		}

		public IEnumerable<DerObjectIdentifier> BagAttributeKeys
		{
			get { return CollectionUtilities.Proxy(m_attributes.Keys); }
		}

		public bool HasFriendlyName
		{
			get { return m_attributes.ContainsKey(PkcsObjectIdentifiers.Pkcs9AtFriendlyName); }
		}
		public void SetFriendlyName(String friendlyName)
		{
			if (HasFriendlyName)
			{
				m_attributes.Remove(PkcsObjectIdentifiers.Pkcs9AtFriendlyName);
			}
			m_attributes.Add(PkcsObjectIdentifiers.Pkcs9AtFriendlyName, new DerBmpString(friendlyName));
		}
    }
}
