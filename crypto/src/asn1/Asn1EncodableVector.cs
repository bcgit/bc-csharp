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
        internal static readonly Asn1Encodable[] EmptyElements = Array.Empty<Asn1Encodable>();

        private const int DefaultCapacity = 10;

        /// <summary>Create a vector holding the elements of a collection.</summary>
        /// <param name="c">The c.</param>
        /// <returns>The new vector.</returns>
        public static Asn1EncodableVector FromCollection(IReadOnlyCollection<Asn1Encodable> c)
        {
            Asn1EncodableVector v = new Asn1EncodableVector(c.Count);
            v.AddAll((IEnumerable<Asn1Encodable>)c);
            return v;
        }

        /// <summary>Create a vector holding a single element.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The new vector.</returns>
        public static Asn1EncodableVector FromElement(Asn1Encodable element) => new Asn1EncodableVector(1){ element };

        /// <summary>Create a vector holding the elements of a sequence.</summary>
        /// <param name="e">The exception.</param>
        /// <returns>The new vector.</returns>
        public static Asn1EncodableVector FromEnumerable(IEnumerable<Asn1Encodable> e)
        {
            Asn1EncodableVector v = new Asn1EncodableVector();
            v.AddAll(e);
            return v;
        }

        private Asn1Encodable[] m_elements;
        private int m_elementCount;
        private bool m_copyOnWrite;

        /// <summary>Create a new <see cref="Asn1EncodableVector"/>.</summary>
        public Asn1EncodableVector()
            : this(DefaultCapacity)
        {
        }

        /// <summary>Create a new <see cref="Asn1EncodableVector"/>.</summary>
        /// <param name="initialCapacity">The initial capacity.</param>
        public Asn1EncodableVector(int initialCapacity)
        {
            if (initialCapacity < 0)
                throw new ArgumentException("must not be negative", nameof(initialCapacity));

            m_elements = initialCapacity == 0 ? EmptyElements : new Asn1Encodable[initialCapacity];
            m_elementCount = 0;
            m_copyOnWrite = false;
        }

        /// <summary>Create a new <see cref="Asn1EncodableVector"/>.</summary>
        /// <param name="element">The element.</param>
        public Asn1EncodableVector(Asn1Encodable element)
            : this()
        {
            Add(element);
        }

        /// <summary>Create a new <see cref="Asn1EncodableVector"/>.</summary>
        /// <param name="element1">The element 1.</param>
        /// <param name="element2">The element 2.</param>
        public Asn1EncodableVector(Asn1Encodable element1, Asn1Encodable element2)
            : this()
        {
            Add(element1);
            Add(element2);
        }

        /// <summary>Create a new <see cref="Asn1EncodableVector"/>.</summary>
        /// <param name="v">The v.</param>
        public Asn1EncodableVector(params Asn1Encodable[] v)
            : this()
        {
            Add(v);
        }

        /// <summary>Add an element to the vector.</summary>
        /// <param name="element">The element.</param>
        public void Add(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            PrepareCapacity(1);

            m_elements[m_elementCount++] = element;
        }

        /// <summary>Add two elements to the vector.</summary>
        /// <param name="element1">The element 1.</param>
        /// <param name="element2">The element 2.</param>
        public void Add(Asn1Encodable element1, Asn1Encodable element2)
        {
            Add(element1);
            Add(element2);
        }

        /// <summary>Add elements to the vector.</summary>
        /// <param name="objs">The elements to add.</param>
        public void Add(params Asn1Encodable[] objs)
        {
            foreach (Asn1Encodable obj in objs)
            {
                Add(obj);
            }
        }

        /// <summary>Add an element to the vector if it is not null.</summary>
        /// <param name="element">The element, or null.</param>
        public void AddOptional(Asn1Encodable element)
        {
            if (element != null)
            {
                Add(element);
            }
        }

        /// <summary>Add each of two elements to the vector if it is not null.</summary>
        /// <param name="element1">The first element, or null.</param>
        /// <param name="element2">The second element, or null.</param>
        public void AddOptional(Asn1Encodable element1, Asn1Encodable element2)
        {
            AddOptional(element1);
            AddOptional(element2);
        }

        /// <summary>Add each of the elements to the vector if it is not null.</summary>
        /// <param name="elements">The elements, any of which may be null.</param>
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

        /// <summary>Add an element to the vector in a context-specific tagged object, if it is not null.</summary>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="obj">The element, or null.</param>
        // TODO[api] Rename 'isExplicit' to 'declaredExplicit', 'obj' to 'element'
        public void AddOptionalTagged(bool isExplicit, int tagNo, Asn1Encodable obj)
        {
            if (null != obj)
            {
                AddTagged(isExplicit, tagNo, obj);
            }
        }

        /// <summary>Add an element to the vector in a tagged object, if it is not null.</summary>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="obj">The element, or null.</param>
        // TODO[api] Rename 'isExplicit' to 'declaredExplicit', 'obj' to 'element'
        public void AddOptionalTagged(bool isExplicit, int tagClass, int tagNo, Asn1Encodable obj)
        {
            if (null != obj)
            {
                AddTagged(isExplicit, tagClass, tagNo, obj);
            }
        }

        /// <summary>Add an element to the vector in a context-specific tagged object.</summary>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="element">The element.</param>
        public void AddTagged(bool declaredExplicit, int tagNo, Asn1Encodable element)
        {
            Add(new DerTaggedObject(declaredExplicit, tagNo, element));
        }

        /// <summary>Add an element to the vector in a tagged object.</summary>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <param name="tagClass">The tag class.</param>
        /// <param name="tagNo">The tag number.</param>
        /// <param name="element">The element.</param>
        public void AddTagged(bool declaredExplicit, int tagClass, int tagNo, Asn1Encodable element)
        {
            Add(new DerTaggedObject(declaredExplicit, tagClass, tagNo, element));
        }

        /// <summary>Add all the elements of a sequence to the vector.</summary>
        /// <param name="e">The elements to add.</param>
        public void AddAll(IEnumerable<Asn1Encodable> e)
        {
            if (e == null)
                throw new ArgumentNullException(nameof(e));

            foreach (Asn1Encodable obj in e)
            {
                Add(obj);
            }
        }

        /// <summary>Add all the elements of a collection to the vector.</summary>
        /// <param name="c">The elements to add.</param>
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

        /// <summary>Add all the elements of another vector to this vector.</summary>
        /// <param name="other">The vector whose elements are added.</param>
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

        /// <summary>Gets the element at the given index.</summary>
        /// <param name="index">The index.</param>
        public Asn1Encodable this[int index]
        {
            get
            {
                if (index >= m_elementCount)
                    throw new IndexOutOfRangeException(index + " >= " + m_elementCount);

                return m_elements[index];
            }
        }

        /// <summary>Gets the count.</summary>
        public int Count => m_elementCount;

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        /// <summary>Return the enumerator.</summary>
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
