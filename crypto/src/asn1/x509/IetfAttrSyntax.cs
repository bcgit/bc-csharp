using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * Implementation of <code>IetfAttrSyntax</code> as specified by RFC3281.
     */
    public class IetfAttrSyntax
        : Asn1Encodable
    {
        /// <summary>The <c>ValueOctets</c> constant, with the value <c>1</c>.</summary>
        public const int ValueOctets = 1;
        /// <summary>The <c>ValueOid</c> constant, with the value <c>2</c>.</summary>
        public const int ValueOid = 2;
        /// <summary>The <c>ValueUtf8</c> constant, with the value <c>3</c>.</summary>
        public const int ValueUtf8 = 3;

        /// <summary>Return an <see cref="IetfAttrSyntax"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="IetfAttrSyntax"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="IetfAttrSyntax"/>, or null if <paramref name="obj"/> is null.</returns>
        public static IetfAttrSyntax GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is IetfAttrSyntax ietfAttrSyntax)
                return ietfAttrSyntax;
#pragma warning disable CS0618 // Type or member is obsolete
            return new IetfAttrSyntax(Asn1Sequence.GetInstance(obj));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="IetfAttrSyntax"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IetfAttrSyntax"/>.</returns>
        public static IetfAttrSyntax GetInstance(Asn1TaggedObject obj, bool isExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new IetfAttrSyntax(Asn1Sequence.GetInstance(obj, isExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        /// <summary>Return an <see cref="IetfAttrSyntax"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="IetfAttrSyntax"/>.</returns>
        public static IetfAttrSyntax GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit)
        {
#pragma warning disable CS0618 // Type or member is obsolete
            return new IetfAttrSyntax(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));
#pragma warning restore CS0618 // Type or member is obsolete
        }

        private readonly GeneralNames m_policyAuthority;
        private readonly Asn1Sequence m_values;
        private readonly int m_valueChoice = -1;

        /// <summary>Create a new <see cref="IetfAttrSyntax"/>.</summary>
        /// <param name="seq">The ASN.1 sequence.</param>
        [Obsolete("Use 'GetInstance' instead")]
        public IetfAttrSyntax(Asn1Sequence seq)
        {
            if (seq == null)
                throw new ArgumentNullException(nameof(seq));

            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_policyAuthority = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, GeneralNames.GetTagged);
            m_values = Asn1Utilities.Read(seq, ref pos, Asn1Sequence.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            int valueChoice = -1;
            foreach (var obj in m_values)
            {
                int type;
                if (obj is DerObjectIdentifier)
                {
                    type = ValueOid;
                }
                else if (obj is DerUtf8String)
                {
                    type = ValueUtf8;
                }
                else if (obj is DerOctetString)
                {
                    type = ValueOctets;
                }
                else
                {
                    throw new ArgumentException("Bad value type encoding IetfAttrSyntax");
                }

                if (valueChoice < 0)
                {
                    valueChoice = type;
                }
                else if (type != valueChoice)
                {
                    throw new ArgumentException("Mix of value types in IetfAttrSyntax");
                }
            }

            m_valueChoice = valueChoice;
        }

        /// <summary>Gets the policy authority.</summary>
        public GeneralNames PolicyAuthority => m_policyAuthority;

        /// <summary>Gets the value type.</summary>
        public int ValueType => m_valueChoice;

        /// <summary>Return the values.</summary>
        public object[] GetValues()
        {
            switch (m_valueChoice)
            {
            case ValueOctets:
                return m_values.MapElements(Asn1OctetString.GetInstance);
            case ValueOid:
                return m_values.MapElements(DerObjectIdentifier.GetInstance);
            case ValueUtf8:
                return m_values.MapElements(DerUtf8String.GetInstance);
            default:
                return Array.Empty<object>();
            }
        }

        /**
         *
         * <pre>
         *
         *  IetfAttrSyntax ::= Sequence {
         *    policyAuthority [0] GeneralNames OPTIONAL,
         *    values Sequence OF CHOICE {
         *      octets OCTET STRING,
         *      oid OBJECT IDENTIFIER,
         *      string UTF8String
         *    }
         *  }
         *
         * </pre>
         */
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_policyAuthority);
            v.Add(m_values);
            return new DerSequence(v);
        }
    }
}
