using System;

using Org.BouncyCastle.Asn1.Cmp;
using Org.BouncyCastle.Asn1.X509;

namespace Org.BouncyCastle.Asn1.Crmf
{
    /**
     * Password-based MAC value for use with POPOSigningKeyInput.
     */
    public class PKMacValue
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="PKMacValue"/> from the given object.</summary>
        /// <param name="obj">An <see cref="PKMacValue"/>, an object from which one can be constructed, or null.</param>
        /// <returns>The <see cref="PKMacValue"/>, or null if <paramref name="obj"/> is null.</returns>
        public static PKMacValue GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is PKMacValue pkMacValue)
                return pkMacValue;
            return new PKMacValue(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="PKMacValue"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="isExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PKMacValue"/>.</returns>
        public static PKMacValue GetInstance(Asn1TaggedObject obj, bool isExplicit) =>
            new PKMacValue(Asn1Sequence.GetInstance(obj, isExplicit));

        /// <summary>Return an <see cref="PKMacValue"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="PKMacValue"/>, or null if <paramref name="element"/> is null.</returns>
        public static PKMacValue GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is PKMacValue pkMacValue)
                return pkMacValue;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new PKMacValue(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="PKMacValue"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="PKMacValue"/>.</returns>
        public static PKMacValue GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new PKMacValue(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly AlgorithmIdentifier m_algID;
        private readonly DerBitString m_macValue;

        private PKMacValue(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_algID = Asn1Utilities.Read(seq, ref pos, AlgorithmIdentifier.GetInstance);
            m_macValue = Asn1Utilities.Read(seq, ref pos, DerBitString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /**
         * Creates a new PKMACValue.
         * @param params parameters for password-based MAC
         * @param value MAC of the DER-encoded SubjectPublicKeyInfo
         */
        public PKMacValue(PbmParameter pbmParams, DerBitString macValue)
            : this(new AlgorithmIdentifier(CmpObjectIdentifiers.passwordBasedMac, pbmParams), macValue)
        {
        }

        /**
         * Creates a new PKMACValue.
         * @param aid CMPObjectIdentifiers.passwordBasedMAC, with PBMParameter
         * @param value MAC of the DER-encoded SubjectPublicKeyInfo
         */
        public PKMacValue(AlgorithmIdentifier algID, DerBitString macValue)
        {
            m_algID = algID;
            m_macValue = macValue;
        }

        /// <summary>Gets the alg ID.</summary>
        public virtual AlgorithmIdentifier AlgID => m_algID;

        /// <summary>Gets the mac value.</summary>
        public virtual DerBitString MacValue => m_macValue;

        /**
         * <pre>
         * PKMACValue ::= SEQUENCE {
         *      algId  AlgorithmIdentifier,
         *      -- algorithm value shall be PasswordBasedMac 1.2.840.113533.7.66.13
         *      -- parameter value is PBMParameter
         *      value  BIT STRING }
         * </pre>
         * @return a basic ASN.1 object representation.
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_algID, m_macValue);
    }
}
