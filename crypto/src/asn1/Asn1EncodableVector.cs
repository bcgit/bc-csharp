using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Asn1
{
    /**
     * Mutable class for building ASN.1 constructed objects such as SETs or SEQUENCEs.
     */
    public class Asn1EncodableVector
        : IReadOnlyCollection<Asn1Encodable>
    {
        internal static readonly Asn1Encodable[] EmptyElements = new Asn1Encodable[0];

        private const int DefaultCapacity = 10;

        public static Asn1EncodableVector FromCollection(IReadOnlyCollection<Asn1Encodable> c)
        {
            Asn1EncodableVector v = new Asn1EncodableVector(c.Count);
            v.AddAll((IEnumerable<Asn1Encodable>)c);
            return v;
        }

        public static Asn1EncodableVector FromElement(Asn1Encodable element) => new Asn1EncodableVector(1){ element };

        public static Asn1EncodableVector FromEnumerable(IEnumerable<Asn1Encodable> e)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.AddAll(e);
            return v;
        }

        private Asn1Encodable[] m_elements;
        private int m_elementCount;
        private bool m_copyOnWrite;

        public Asn1EncodableVector()
            : this(DefaultCapacity)
        {
        }

        public Asn1EncodableVector(int initialCapacity)
        {
            if (initialCapacity < 0)
                throw new ArgumentException("must not be negative", nameof(initialCapacity));

            m_elements = initialCapacity == 0 ? EmptyElements : new Asn1Encodable[initialCapacity];
            m_elementCount = 0;
            m_copyOnWrite = false;
        }

        public Asn1EncodableVector(Asn1Encodable element)
            : this()
        {
            Add(element);
        }

        public Asn1EncodableVector(Asn1Encodable element1, Asn1Encodable element2)
            : this()
        {
            Add(element1);
            Add(element2);
        }

        public Asn1EncodableVector(params Asn1Encodable[] v)
            : this()
        {
            Add(v);
        }

        public void Add(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            PrepareCapacity(1);

            m_elements[m_elementCount++] = element;
        }

        public void Add(Asn1Encodable element1, Asn1Encodable element2)
        {
            Add(element1);
            Add(element2);
        }

        public void Add(params Asn1Encodable[] objs)
        {
            foreach (Asn1Encodable obj in objs)
            {
                Add(obj);
            }
        }

        public void AddOptional(Asn1Encodable element)
        {
            if (element != null)
            {
                Add(element);
            }
        }

        public void AddOptional(Asn1Encodable element1, Asn1Encodable element2)
        {
            AddOptional(element1);
            AddOptional(element2);
        }

        public void AddOptional(params Asn1Encodable[] elements)
        {
            if (elements != null)
            {
                foreach (var element in elements)
                {
                    AddOptional(element);
                }
            }
        }

        public void AddOptionalTagged(bool isExplicit, int tagNo, Asn1Encodable obj)
        {
            if (null != obj)
            {
                Add(new DerTaggedObject(isExplicit, tagNo, obj));
            }
        }

        public void AddOptionalTagged(bool isExplicit, int tagClass, int tagNo, Asn1Encodable obj)
        {
            if (null != obj)
            {
                Add(new DerTaggedObject(isExplicit, tagClass, tagNo, obj));
            }
        }

        public void AddAll(IEnumerable<Asn1Encodable> e)
        {
            if (e == null)
                throw new ArgumentNullException(nameof(e));

            foreach (Asn1Encodable obj in e)
            {
                Add(obj);
            }
        }

        public void AddAll(IReadOnlyCollection<Asn1Encodable> c)
        {
            if (c == null)
                throw new ArgumentNullException(nameof(c));

            int otherElementCount = c.Count;
            if (otherElementCount < 1)
                return;

            PrepareCapacity(otherElementCount);

            AddAll((IEnumerable<Asn1Encodable>)c);
        }

        public void AddAll(Asn1EncodableVector other)
        {
            if (other == null)
                throw new ArgumentNullException(nameof(other));

            int otherElementCount = other.Count;
            if (otherElementCount < 1)
                return;

            PrepareCapacity(otherElementCount);

            Array.Copy(other.m_elements, 0, m_elements, m_elementCount, otherElementCount);
            m_elementCount += otherElementCount;
        }

        public Asn1Encodable this[int index]
        {
            get
            {
                if (index >= m_elementCount)
                    throw new IndexOutOfRangeException(index + " >= " + m_elementCount);

                return m_elements[index];
            }
        }

        public int Count => m_elementCount;

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public IEnumerator<Asn1Encodable> GetEnumerator()
        {
            IEnumerable<Asn1Encodable> e = EnumerateElements(m_elements, m_elementCount);
            return e.GetEnumerator();
        }

        internal Asn1Encodable[] CopyElements() => CopyElements(m_elements, m_elementCount);

        internal Asn1Encodable[] TakeElements()
        {
            if (m_elementCount == 0)
                return EmptyElements;

            if (m_elements.Length == m_elementCount)
            {
                m_copyOnWrite = true;
                return m_elements;
            }

            Asn1Encodable[] copy = new Asn1Encodable[m_elementCount];
            Array.Copy(m_elements, 0, copy, 0, m_elementCount);
            return copy;
        }

        private int PrepareCapacity(int requiredCapacity)
        {
            int capacity = m_elements.Length;
            int minCapacity = m_elementCount + requiredCapacity;
            if ((minCapacity > capacity) | m_copyOnWrite)
            {
                Reallocate(minCapacity);
            }
            return minCapacity;
        }

        private void Reallocate(int minCapacity)
        {
            int oldCapacity = m_elements.Length;
            int newCapacity = System.Math.Max(oldCapacity, minCapacity + (minCapacity >> 1));

            Asn1Encodable[] copy = new Asn1Encodable[newCapacity];
            Array.Copy(m_elements, 0, copy, 0, m_elementCount);

            m_elements = copy;
            m_copyOnWrite = false;
        }

        internal static Asn1Encodable[] CloneElements(Asn1Encodable[] elements) =>
            CopyElements(elements, elementCount: elements.Length);

        private static Asn1Encodable[] CopyElements(Asn1Encodable[] elements, int elementCount)
        {
            if (elementCount < 1)
                return EmptyElements;

            Asn1Encodable[] copy = new Asn1Encodable[elementCount];
            Array.Copy(elements, 0, copy, 0, elementCount);
            return copy;
        }

        private static IEnumerable<Asn1Encodable> EnumerateElements(Asn1Encodable[] elements, int elementCount)
        {
            for (int i = 0; i < elementCount; ++i)
                yield return elements[i];
        }
    }
}
