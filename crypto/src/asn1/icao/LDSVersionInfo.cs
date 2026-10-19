using System;

namespace Org.BouncyCastle.Asn1.Icao
{
    /// <summary>The LDSVersionInfo structure of the ICAO machine readable travel documents specification.</summary>
    public class LdsVersionInfo
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="LdsVersionInfo"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="LdsVersionInfo"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="LdsVersionInfo"/>, or null if <paramref name="obj"/> is null.</returns>
        public static LdsVersionInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is LdsVersionInfo ldsVersionInfo)
                return ldsVersionInfo;
            return new LdsVersionInfo(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="LdsVersionInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="LdsVersionInfo"/>.</returns>
        public static LdsVersionInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LdsVersionInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="LdsVersionInfo"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="LdsVersionInfo"/>, or null if <paramref name="element"/> is null.</returns>
        public static LdsVersionInfo GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is LdsVersionInfo ldsVersionInfo)
                return ldsVersionInfo;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new LdsVersionInfo(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="LdsVersionInfo"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="LdsVersionInfo"/>.</returns>
        public static LdsVersionInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LdsVersionInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private DerPrintableString m_ldsVersion;
        private DerPrintableString m_unicodeVersion;

        private LdsVersionInfo(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_ldsVersion = Asn1Utilities.Read(seq, ref pos, DerPrintableString.GetInstance);
            m_unicodeVersion = Asn1Utilities.Read(seq, ref pos, DerPrintableString.GetInstance);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        /// <summary>Create a new <see cref="LdsVersionInfo"/>.</summary>
        /// <param name="ldsVersion">The lds version.</param>
        /// <param name="unicodeVersion">The unicode version.</param>
        public LdsVersionInfo(string ldsVersion, string unicodeVersion)
        {
            m_ldsVersion = new DerPrintableString(ldsVersion);
            m_unicodeVersion = new DerPrintableString(unicodeVersion);
        }

        /// <summary>Return the lds version.</summary>
        public virtual string GetLdsVersion() => m_ldsVersion.GetString();

        /// <summary>Return the unicode version.</summary>
        public virtual string GetUnicodeVersion() => m_unicodeVersion.GetString();

        /**
         * <pre>
         * LDSVersionInfo ::= SEQUENCE {
         *    ldsVersion PRINTABLE STRING
         *    unicodeVersion PRINTABLE STRING
         *  }
         * </pre>
         * @return
         */
        public override Asn1Object ToAsn1Object() => new DerSequence(m_ldsVersion, m_unicodeVersion);
    }
}
