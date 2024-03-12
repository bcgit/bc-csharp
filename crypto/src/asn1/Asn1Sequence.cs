using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;

namespace Org.BouncyCastle.Asn1
{
    public abstract class Asn1Sequence
        : Asn1Object, IEnumerable<Asn1Encodable>
    {
        internal class Meta : Asn1UniversalType
        {
            internal static readonly Asn1UniversalType Instance = new Meta();

            private Meta() : base(typeof(Asn1Sequence), Asn1Tags.Sequence) {}

            internal override Asn1Object FromImplicitConstructed(Asn1Sequence sequence)
            {
                return sequence;
            }
        }

        /**
         * return an Asn1Sequence from the given object.
         *
         * @param obj the object we want converted.
         * @exception ArgumentException if the object cannot be converted.
         */
        public static Asn1Sequence GetInstance(object obj)
        {
            if (obj == null)
                return null;

            if (obj is Asn1Sequence asn1Sequence)
                return asn1Sequence;

            if (obj is IAsn1Convertible asn1Convertible)
            {
                Asn1Object asn1Object = asn1Convertible.ToAsn1Object();
                if (asn1Object is Asn1Sequence converted)
                    return converted;
            }
            else if (obj is byte[] bytes)
            {
                try
                {
                    return (Asn1Sequence)Meta.Instance.FromByteArray(bytes);
                }
                catch (IOException e)
                {
                    throw new ArgumentException("failed to construct sequence from byte[]: " + e.Message);
                }
            }

            throw new ArgumentException("illegal object in GetInstance: " + Platform.GetTypeName(obj), "obj");
        }

        /**
         * Return an ASN1 sequence from a tagged object. There is a special
         * case here, if an object appears to have been explicitly tagged on
         * reading but we were expecting it to be implicitly tagged in the
         * normal course of events it indicates that we lost the surrounding
         * sequence - so we need to add it back (this will happen if the tagged
         * object is a sequence that contains other sequences). If you are
         * dealing with implicitly tagged sequences you really <b>should</b>
         * be using this method.
         *
         * @param taggedObject the tagged object.
         * @param declaredExplicit true if the object is meant to be explicitly tagged, false otherwise.
         * @exception ArgumentException if the tagged object cannot be converted.
         */
        public static Asn1Sequence GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
            return (Asn1Sequence)Meta.Instance.GetContextInstance(taggedObject, declaredExplicit);
        }

        internal readonly Asn1Encodable[] m_elements;

        protected internal Asn1Sequence()
        {
            m_elements = Asn1EncodableVector.EmptyElements;
        }

        protected internal Asn1Sequence(Asn1Encodable element)
        {
            if (null == element)
                throw new ArgumentNullException(nameof(element));

            m_elements = new Asn1Encodable[]{ element };
        }

        protected internal Asn1Sequence(Asn1Encodable element1, Asn1Encodable element2)
        {
            if (null == element1)
                throw new ArgumentNullException(nameof(element1));
            if (null == element2)
                throw new ArgumentNullException(nameof(element2));

            m_elements = new Asn1Encodable[]{ element1, element2 };
        }

        protected internal Asn1Sequence(params Asn1Encodable[] elements)
        {
            if (Arrays.IsNullOrContainsNull(elements))
                throw new NullReferenceException("'elements' cannot be null, or contain null");

            m_elements = Asn1EncodableVector.CloneElements(elements);
        }

        internal Asn1Sequence(Asn1Encodable[] elements, bool clone)
        {
            m_elements = clone ? Asn1EncodableVector.CloneElements(elements) : elements;
        }

        protected internal Asn1Sequence(Asn1EncodableVector elementVector)
        {
            if (null == elementVector)
                throw new ArgumentNullException("elementVector");

            m_elements = elementVector.TakeElements();
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

        private class Asn1SequenceParserImpl
            : Asn1SequenceParser
        {
            private readonly Asn1Sequence m_outer;
            private int m_index;

            public Asn1SequenceParserImpl(Asn1Sequence outer)
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

            public Asn1Object ToAsn1Object() => m_outer;
        }

        public virtual Asn1SequenceParser Parser
        {
            get { return new Asn1SequenceParserImpl(this); }
        }

        /**
         * return the object at the sequence position indicated by index.
         *
         * @param index the sequence number (starting at zero) of the object
         * @return the object at the sequence position indicated by index.
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
            if (!(asn1Object is Asn1Sequence that))
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

        // TODO[asn1] Preferably return an Asn1BitString[] (doesn't exist yet)
        internal DerBitString[] GetConstructedBitStrings()
        {
            return MapElements(DerBitString.GetInstance);
        }

        internal Asn1OctetString[] GetConstructedOctetStrings()
        {
            return MapElements(Asn1OctetString.GetInstance);
        }

        // TODO[asn1] Preferably return an Asn1BitString (doesn't exist yet)
        internal abstract DerBitString ToAsn1BitString();

        // TODO[asn1] Preferably return an Asn1External (doesn't exist yet)
        internal abstract DerExternal ToAsn1External();

        internal abstract Asn1OctetString ToAsn1OctetString();

        internal abstract Asn1Set ToAsn1Set();
    }
}
