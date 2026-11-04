using System;

namespace Org.BouncyCastle.Asn1.X509
{
    /*
     *  Extension ::= SEQUENCE {
     *      extnID      OBJECT IDENTIFIER,
     *      critical    BOOLEAN DEFAULT FALSE,
     *      extnValue   OCTET STRING
     *                  -- contains the DER encoding of an ASN.1 value
     *                  -- corresponding to the extension type identified
     *                  -- by extnID
     *  }
     */
    public class Extension
        : Asn1Encodable
    {
        private static readonly DerBoolean DefaultCritical = DerBoolean.False;

        /// <summary>Return an <see cref="Extension"/> from the given object.</summary>
        /// <param name="obj">An <see cref="Extension"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="Extension"/>, or null if <paramref name="obj"/> is null.</returns>
        public static Extension GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is Extension extension)
                return extension;
            return new Extension(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="Extension"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Extension"/>.</returns>
        public static Extension GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Extension(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="Extension"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="Extension"/>, or null if <paramref name="element"/> is null.</returns>
        public static Extension GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is Extension existing)
                return existing;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new Extension(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="Extension"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="Extension"/>.</returns>
        public static Extension GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new Extension(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DerObjectIdentifier m_extnID;
        private readonly DerBoolean m_critical;
        private readonly Asn1OctetString m_extnValue;

        private Extension(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 2 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_extnID = Asn1Utilities.Read(seq, ref pos, DerObjectIdentifier.GetInstance);
            m_critical = Asn1Utilities.ReadOptional(seq, ref pos, DerBoolean.GetOptional) ?? DefaultCritical;
            m_extnValue = Asn1Utilities.Read(seq, ref pos, Asn1OctetString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="Extension"/>.</summary>
        /// <param name="extnID">The extn ID.</param>
        /// <param name="critical">Whether the extension is critical.</param>
        /// <param name="extnValue">The extn value.</param>
        public Extension(DerObjectIdentifier extnID, DerBoolean critical, Asn1OctetString extnValue)
        {
            m_extnID = extnID ?? throw new ArgumentNullException(nameof(extnID));
            m_critical = critical ?? DefaultCritical;
            m_extnValue = extnValue ?? throw new ArgumentNullException(nameof(extnValue));
        }

        /// <summary>Gets the critical.</summary>
        public DerBoolean Critical => m_critical;

        /// <summary>Gets the extn ID.</summary>
        public DerObjectIdentifier ExtnID => m_extnID;

        /// <summary>Gets the extn value.</summary>
        public Asn1OctetString ExtnValue => m_extnValue;

        /// <summary>Return the parsed value.</summary>
        public Asn1Object GetParsedValue() => ConvertValueToObject(m_extnValue);

        /// <summary>Return the x 509 extension.</summary>
        public X509Extension GetX509Extension() => new X509Extension(m_critical, m_extnValue);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object()
        {
            return DefaultCritical.Equals(m_critical)
                ?   new DerSequence(m_extnID, m_extnValue)
                :   new DerSequence(m_extnID, m_critical, m_extnValue);
        }

        internal static Asn1Object ConvertValueToObject(Asn1OctetString extnValue)
        {
            try
            {
                return Asn1Object.FromByteArray(extnValue.GetOctets());
            }
            catch (Exception e)
            {
                throw new ArgumentException("can't convert extension", e);
            }
        }
    }
}
