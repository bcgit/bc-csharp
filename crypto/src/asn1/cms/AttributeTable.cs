using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Org.BouncyCastle.Asn1.Cms
{
    public class AttributeTable
        : IReadOnlyCollection<Attribute>
    {
        private readonly Dictionary<DerObjectIdentifier, object> m_attributes;
        private readonly int m_count;

        public AttributeTable(IDictionary<DerObjectIdentifier, object> attrs)
        {
            m_attributes = BuildAttributes(attrs, out m_count);
        }

        public AttributeTable(Asn1EncodableVector v)
        {
            m_attributes = BuildAttributes(v, out m_count);
        }

        public AttributeTable(IReadOnlyCollection<Attribute> attributes)
        {
            m_attributes = BuildAttributes(attributes, out m_count);
        }

        public AttributeTable(Asn1Set s)
        {
            m_attributes = BuildAttributes(s, out m_count);
        }

        public AttributeTable(Attributes attrs)
            : this(Asn1Set.GetInstance(attrs.ToAsn1Object()))
        {
        }

        private AttributeTable(Dictionary<DerObjectIdentifier, object> attributes, int count)
        {
            m_attributes = attributes;
            m_count = count;
        }

        /// <summary>Return the first attribute matching the given OBJECT IDENTIFIER</summary>
        public Attribute this[DerObjectIdentifier oid]
        {
            get
            {
                if (!m_attributes.TryGetValue(oid, out object existingValue))
                    return null;

                if (existingValue is List<Attribute> existingList)
                    return existingList[0];

                if (existingValue is Attribute existingAttr)
                    return existingAttr;

                throw new InvalidOperationException();
            }
        }

        public int Count => m_count;

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();

        public virtual IEnumerator<Attribute> GetEnumerator()
        {
            IEnumerable<Attribute> e = EnumerateAttributes(m_attributes);
            return e.GetEnumerator();
        }

        /**
        * Return all the attributes matching the OBJECT IDENTIFIER oid. The vector will be
        * empty if there are no attributes of the required type present.
        *
        * @param oid type of attribute required.
        * @return a vector of all the attributes found of type oid.
        */
        public Asn1EncodableVector GetAll(DerObjectIdentifier oid)
        {
            if (!m_attributes.TryGetValue(oid, out object existingValue))
                return new Asn1EncodableVector(0);

            if (existingValue is List<Attribute> existingList)
                return Asn1EncodableVector.FromCollection(existingList);

            if (existingValue is Attribute existingAttr)
                return Asn1EncodableVector.FromElement(existingAttr);

            throw new InvalidOperationException();
        }

        public IDictionary<DerObjectIdentifier, object> ToDictionary() => BuildAttributes(m_attributes, out var ignore);

        public Asn1EncodableVector ToAsn1EncodableVector() => Asn1EncodableVector.FromCollection(this);

        public Attributes ToAttributes() => new Attributes(this);

        public AttributeTable Add(params Attribute[] attributes)
        {
            if (attributes == null || attributes.Length < 1)
                return this;

            var newAttributes = BuildAttributes(m_attributes, out int newCount);
            Debug.Assert(m_count == newCount);
            foreach (Attribute attribute in attributes)
            {
                AddAttribute(newAttributes, attribute);
            }
            newCount += attributes.Length;
            return new AttributeTable(newAttributes, newCount);
        }

        /// <summary>Return a new table with the passed in attribute added.</summary>
        public AttributeTable Add(DerObjectIdentifier attrType, Asn1Encodable attrValue) =>
            Add(new Attribute(attrType, new DerSet(attrValue)));

        public AttributeTable Remove(DerObjectIdentifier attrType)
        {
            int countOfType = CountAttributesOfType(m_attributes, attrType);
            if (countOfType < 1)
                return this;

            var newAttributes = BuildAttributes(m_attributes, out int oldCount);
            Debug.Assert(m_count == oldCount);
            if (!newAttributes.Remove(attrType))
                throw new InvalidOperationException();
            int newCount = oldCount - countOfType;
            return new AttributeTable(newAttributes, newCount);
        }

        private static void AddAttribute(Dictionary<DerObjectIdentifier, object> attributes, Attribute a)
        {
            DerObjectIdentifier oid = a.AttrType;

            if (!attributes.TryGetValue(oid, out object existingValue))
            {
                attributes.Add(oid, a);
            }
            else if (existingValue is List<Attribute> existingList)
            {
                existingList.Add(a);
            }
            else if (existingValue is Attribute existingAttr)
            {
                attributes[oid] = new List<Attribute>(){ existingAttr, a };
            }
            else
            {
                throw new InvalidOperationException();
            }
        }

        private static Dictionary<DerObjectIdentifier, object> BuildAttributes(
            IDictionary<DerObjectIdentifier, object> d, out int count)
        {
            var result = new Dictionary<DerObjectIdentifier, object>();
            count = 0;
            foreach (var entry in d)
            {
                if (entry.Value is List<Attribute> existingList)
                {
                    var copy = new List<Attribute>(existingList);
                    result.Add(entry.Key, copy);
                    count += copy.Count;
                }
                else if (entry.Value is Attribute existingAttr)
                {
                    result.Add(entry.Key, existingAttr);
                    ++count;
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }
            return result;
        }

        private static Dictionary<DerObjectIdentifier, object> BuildAttributes(IReadOnlyCollection<Asn1Encodable> c,
            out int count)
        {
            count = c.Count;
            var result = new Dictionary<DerObjectIdentifier, object>();
            foreach (Asn1Encodable element in c)
            {
                AddAttribute(result, Attribute.GetInstance(element));
            }
            return result;
        }

        private static int CountAttributesOfType(Dictionary<DerObjectIdentifier, object> attributes,
            DerObjectIdentifier attrType)
        {
            if (!attributes.TryGetValue(attrType, out object existingValue))
                return 0;

            if (existingValue is List<Attribute> existingList)
                return existingList.Count;

            if (existingValue is Attribute existingAttr)
                return 1;

            throw new InvalidOperationException();
        }

        private static IEnumerable<Attribute> EnumerateAttributes(Dictionary<DerObjectIdentifier, object> attributes)
        {
            foreach (object existingValue in attributes.Values)
            {
                if (existingValue is List<Attribute> existingList)
                {
                    foreach (Attribute existingAttr in existingList)
                    {
                        yield return existingAttr;
                    }
                }
                else if (existingValue is Attribute existingAttr)
                {
                    yield return existingAttr;
                }
                else
                {
                    throw new InvalidOperationException();
                }
            }
        }
    }

    public static class AttributeTableExtensions
    {
        public static AttributeTable ToAttributeTable(this Asn1EncodableVector v) => new AttributeTable(v);

        public static AttributeTable ToAttributeTable(this IReadOnlyCollection<Attribute> attributes) =>
            new AttributeTable(attributes);

        public static AttributeTable ToAttributeTable(this Asn1Set s) => new AttributeTable(s);
    }
}
