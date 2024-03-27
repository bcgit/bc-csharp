using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Set
        : Asn1Object, IEnumerable<Asn1Encodable>
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1Set), Asn1Tags.Set) {}

            internal override Asn1Object FromImplicitConstructed(Asn1Sequence sequence)
            {
                return sequence.ToAsn1Set();
            }
        }

        /**
         * return an ASN1Set from the given object.
         *
         * @param obj the object we want converted.
         * @exception ArgumentException if the object cannot be converted.
         */
        public static Asn1Set GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1Set asn1Set)
                return asn1Set;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
                if (asn1Object is Asn1Set converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (Asn1Set)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct set from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), nameof(obj));
        }

        /**
         * Return an ASN1 set from a tagged object. There is a special
         * case here, if an object appears to have been explicitly tagged on
         * reading but we were expecting it to be implicitly tagged in the
         * normal course of events it indicates that we lost the surrounding
         * set - so we need to add it back (this will happen if the tagged
         * object is a sequence that contains other sequences). If you are
         * dealing with implicitly tagged sets you really <b>should</b>
         * be using this method.
         *
         * @param taggedObject the tagged object.
         * @param declaredExplicit true if the object is meant to be explicitly tagged false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static Asn1Set GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1Set)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        internal readonly Asn1Encodable[] m_elements;
        internal DerEncoding[] m_sortedDerEncodings;

        protected internal Asn1Set()
        {
            m_elements = Asn1EncodableVector.EmptyElements;
            m_sortedDerEncodings = null;
        }

        protected internal Asn1Set(Asn1Encodable element)
        {
            if (null == element)
                throw new ArgumentNullException(nameof(element));

            m_elements = new Asn1Encodable[]{ element };
            m_sortedDerEncodings = null;
        }

        protected internal Asn1Set(Asn1Encodable[] elements, bool doSort)
        {
            if (Arrays.IsNullOrContainsNull(elements))
                throw new NullReferenceException("'elements' cannot be null, or contain null");

            elements = Asn1EncodableVector.CloneElements(elements);
            DerEncoding[] sortedDerEncodings = null;

            if (doSort && elements.Length > 1)
            {
                sortedDerEncodings = SortElements(elements);
            }

            m_elements = elements;
            m_sortedDerEncodings = sortedDerEncodings;
        }

        protected internal Asn1Set(Asn1EncodableVector elementVector, bool doSort)
        {
            if (null == elementVector)
                throw new ArgumentNullException(nameof(elementVector));

            Asn1Encodable[] elements;
            DerEncoding[] sortedDerEncodings;

            if (doSort && elementVector.Count > 1)
            {
                elements = elementVector.CopyElements();
                sortedDerEncodings = SortElements(elements);
            }
            else
            {
                elements = elementVector.TakeElements();
                sortedDerEncodings = null;
            }

            m_elements = elements;
            m_sortedDerEncodings = sortedDerEncodings;
        }

        protected internal Asn1Set(bool isSorted, Asn1Encodable[] elements)
        {
            Debug.Assert(!isSorted);
            m_elements = elements;
            m_sortedDerEncodings = null;
        }

        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }

        public virtual IEnumerator<Asn1Encodable> GetEnumerator()
        {
            IEnumerable<Asn1Encodable> e = m_elements;
            return e.GetEnumerator();
        }

        /**
         * return the object at the set position indicated by index.
         *
         * @param index the set number (starting at zero) of the object
         * @return the object at the set position indicated by index.
         */
        public virtual Asn1Encodable this[int index]
        {
            get { return m_elements[index]; }
        }

        public virtual int Count
        {
            get { return m_elements.Length; }
        }

        public virtual T[] MapElements<T>(Func<Asn1Encodable, T> func)
        {
            int count = Count;
            T[] result = new T[count];
            for (int i = 0; i < count; ++i)
            {
                result[i] = func(m_elements[i]);
            }
            return result;
        }

        public virtual Asn1Encodable[] ToArray()
        {
            return Asn1EncodableVector.CloneElements(m_elements);
        }

        private class Asn1SetParserImpl
            : Asn1SetParser
        {
            private readonly Asn1Set m_outer;
            private int m_index;

            public Asn1SetParserImpl(Asn1Set outer)
            {
                m_outer = outer;
                m_index = 0;
            }

            public IAsn1Convertible ReadObject()
            {
                var elements = m_outer.m_elements;
                if (m_index >= elements.Length)
                    return null;

                Asn1Encodable obj = elements[m_index++];

                if (obj is Asn1Sequence asn1Sequence)
                    return asn1Sequence.Parser;

                if (obj is Asn1Set asn1Set)
                    return asn1Set.Parser;

                // NB: Asn1OctetString implements Asn1OctetStringParser directly

                return obj;
            }

            public virtual Asn1Object ToAsn1Object() => m_outer;
        }

        public Asn1SetParser Parser
        {
            get { return new Asn1SetParserImpl(this); }
        }

        protected override int Asn1GetHashCode()
        {
            int i = Count;
            int hc = i + 1;

            while (--i >= 0)
            {
                hc *= 257;
                hc ^= m_elements[i].ToAsn1Object().CallAsn1GetHashCode();
            }

            return hc;
        }

        protected override bool Asn1Equals(Asn1Object asn1Object)
        {
            if (!(asn1Object is Asn1Set that))
                return false;

            int count = this.Count;
            if (that.Count != count)
                return false;

            for (int i = 0; i < count; ++i)
            {
                Asn1Object o1 = this.m_elements[i].ToAsn1Object();
                Asn1Object o2 = that.m_elements[i].ToAsn1Object();

                if (!o1.Equals(o2))
                    return false;
            }

            return true;
        }

        public override string ToString()
        {
            return CollectionUtilities.ToString(m_elements);
        }

        private static DerEncoding[] SortElements(Asn1Encodable[] elements)
        {
            var derEncodings = Asn1OutputStream.GetContentsEncodingsDer(elements);
            Array.Sort(derEncodings, elements);
            return derEncodings;
        }
    }
}
