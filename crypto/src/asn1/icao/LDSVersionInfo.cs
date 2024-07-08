using System;

namespace Org.BouncyCastle.Asn1.Icao
{
    public class LdsVersionInfo
		: Asn1Encodable
	{
        public static LdsVersionInfo GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is LdsVersionInfo ldsVersionInfo)
                return ldsVersionInfo;
            return new LdsVersionInfo(Asn1Sequence.GetInstance(obj));
        }

        public static LdsVersionInfo GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LdsVersionInfo(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

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

        public static LdsVersionInfo GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new LdsVersionInfo(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private DerPrintableString m_ldsVersion;
        private DerPrintableString m_unicodeVersion;

        private LdsVersionInfo(Asn1Sequence seq)
		{
            int count = seq.Count;
            if (count != 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_ldsVersion = DerPrintableString.GetInstance(seq[0]);
			m_unicodeVersion = DerPrintableString.GetInstance(seq[1]);
		}

        public LdsVersionInfo(string ldsVersion, string unicodeVersion)
        {
            m_ldsVersion = new DerPrintableString(ldsVersion);
            m_unicodeVersion = new DerPrintableString(unicodeVersion);
        }

		public virtual string GetLdsVersion() => m_ldsVersion.GetString();

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
