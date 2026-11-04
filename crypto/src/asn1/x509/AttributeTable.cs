using System.Collections.Generic;

using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>A table of CMS attributes, keyed by attribute object identifier.</summary>
    public class AttributeTable
    {
        private readonly Dictionary<DerObjectIdentifier, AttributeX509> m_attributes;

        /// <summary>Create a new <see cref="AttributeTable"/>.</summary>
        /// <param name="attrs">The attrs.</param>
        public AttributeTable(IDictionary<DerObjectIdentifier, AttributeX509> attrs)
        {
            m_attributes = new Dictionary<DerObjectIdentifier, AttributeX509>(attrs);
        }

        /// <summary>Create a new <see cref="AttributeTable"/>.</summary>
        /// <param name="v">The v.</param>
        public AttributeTable(Asn1EncodableVector v)
        {
            m_attributes = new Dictionary<DerObjectIdentifier, AttributeX509>(v.Count);

            for (int i = 0; i != v.Count; i++)
            {
                AttributeX509 a = AttributeX509.GetInstance(v[i]);

                m_attributes.Add(a.AttrType, a);
            }
        }

        /// <summary>Create a new <see cref="AttributeTable"/>.</summary>
        /// <param name="s">The s.</param>
        public AttributeTable(Asn1Set s)
        {
            m_attributes = new Dictionary<DerObjectIdentifier, AttributeX509>(s.Count);

            for (int i = 0; i != s.Count; i++)
            {
                AttributeX509 a = AttributeX509.GetInstance(s[i]);

                m_attributes.Add(a.AttrType, a);
            }
        }

        /// <summary>Get the attribute of the given type.</summary>
        /// <param name="oid">The attribute type.</param>
        /// <returns>The attribute, or null if there is none.</returns>
        public AttributeX509 Get(DerObjectIdentifier oid) => CollectionUtilities.GetValueOrNull(m_attributes, oid);

        /// <summary>Return a dictionary mapping attribute types to attributes.</summary>
        /// <returns>A new dictionary.</returns>
        public IDictionary<DerObjectIdentifier, AttributeX509> ToDictionary()
        {
            return new Dictionary<DerObjectIdentifier, AttributeX509>(m_attributes);
        }

        /// <summary>Get the attribute of the given type.</summary>
        /// <param name="attributeType">The attribute type.</param>
        /// <param name="attributeValue">The attribute value.</param>
        /// <returns>The attribute, or null if there is none.</returns>
        public bool TryGet(DerObjectIdentifier attributeType, out AttributeX509 attributeValue) =>
            m_attributes.TryGetValue(attributeType, out attributeValue);
    }
}
