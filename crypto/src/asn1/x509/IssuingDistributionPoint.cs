using System;
using System.Text;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
	 * <pre>
	 * IssuingDistributionPoint ::= SEQUENCE { 
	 *   distributionPoint          [0] DistributionPointName OPTIONAL, 
	 *   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE, 
	 *   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE, 
	 *   onlySomeReasons            [3] ReasonFlags OPTIONAL, 
	 *   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
	 *   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
	 * </pre>
	 */
    public class IssuingDistributionPoint
        : Asn1Encodable
    {
		public static IssuingDistributionPoint GetInstance(object obj)
        {
			if (obj == null)
				return null;
            if (obj is IssuingDistributionPoint issuingDistributionPoint)
                return issuingDistributionPoint;
            return new IssuingDistributionPoint(Asn1Sequence.GetInstance(obj));
		}

        public static IssuingDistributionPoint GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new IssuingDistributionPoint(Asn1Sequence.GetInstance(obj, explicitly));

        public static IssuingDistributionPoint GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new IssuingDistributionPoint(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DistributionPointName m_distributionPoint;
        private readonly DerBoolean m_onlyContainsUserCerts;
        private readonly DerBoolean m_onlyContainsCACerts;
        private readonly ReasonFlags m_onlySomeReasons;
        private readonly DerBoolean m_indirectCRL;
        private readonly DerBoolean m_onlyContainsAttributeCerts;

        private readonly Asn1Sequence m_seq;

        /**
		 * Constructor from given details.
		 * 
		 * @param distributionPoint
		 *            May contain an URI as pointer to most current CRL.
		 * @param onlyContainsUserCerts Covers revocation information for end certificates.
		 * @param onlyContainsCACerts Covers revocation information for CA certificates.
		 * 
		 * @param onlySomeReasons
		 *            Which revocation reasons does this point cover.
		 * @param indirectCRL
		 *            If <code>true</code> then the CRL contains revocation
		 *            information about certificates ssued by other CAs.
		 * @param onlyContainsAttributeCerts Covers revocation information for attribute certificates.
		 */
        public IssuingDistributionPoint(
			DistributionPointName	distributionPoint,
			bool					onlyContainsUserCerts,
			bool					onlyContainsCACerts,
			ReasonFlags				onlySomeReasons,
			bool					indirectCRL,
			bool					onlyContainsAttributeCerts)
		{
			m_distributionPoint = distributionPoint;
            m_onlyContainsUserCerts = DerBoolean.GetInstance(onlyContainsUserCerts);
            m_onlyContainsCACerts = DerBoolean.GetInstance(onlyContainsCACerts);
            m_onlySomeReasons = onlySomeReasons;
            m_indirectCRL = DerBoolean.GetInstance(indirectCRL);
			m_onlyContainsAttributeCerts = DerBoolean.GetInstance(onlyContainsAttributeCerts);

			Asn1EncodableVector vec = new Asn1EncodableVector(6);
			if (distributionPoint != null)
			{	// CHOICE item so explicitly tagged
				vec.Add(new DerTaggedObject(true, 0, distributionPoint));
			}
			if (onlyContainsUserCerts)
			{
				vec.Add(new DerTaggedObject(false, 1, DerBoolean.True));
			}
			if (onlyContainsCACerts)
			{
				vec.Add(new DerTaggedObject(false, 2, DerBoolean.True));
			}
			if (onlySomeReasons != null)
			{
				vec.Add(new DerTaggedObject(false, 3, onlySomeReasons));
			}
			if (indirectCRL)
			{
				vec.Add(new DerTaggedObject(false, 4, DerBoolean.True));
			}
			if (onlyContainsAttributeCerts)
			{
				vec.Add(new DerTaggedObject(false, 5, DerBoolean.True));
			}

			m_seq = new DerSequence(vec);
		}

		/**
         * Constructor from Asn1Sequence
         */
        private IssuingDistributionPoint(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 6)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_distributionPoint = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true,
				DistributionPointName.GetTagged); // CHOICE
            m_onlyContainsUserCerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false, DerBoolean.GetTagged)
				?? DerBoolean.False;
            m_onlyContainsCACerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, DerBoolean.GetTagged)
                ?? DerBoolean.False;
            m_onlySomeReasons = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 3, false,
				(t, e) => new ReasonFlags(ReasonFlags.GetInstance(t, e)));
            m_indirectCRL = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 4, false, DerBoolean.GetTagged)
                ?? DerBoolean.False;
            m_onlyContainsAttributeCerts = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 5, false, DerBoolean.GetTagged)
                ?? DerBoolean.False;

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

            m_seq = seq;
        }

		public bool OnlyContainsUserCerts => m_onlyContainsUserCerts.IsTrue;

		public bool OnlyContainsCACerts => m_onlyContainsCACerts.IsTrue;

		public bool IsIndirectCrl => m_indirectCRL.IsTrue;

		public bool OnlyContainsAttributeCerts => m_onlyContainsAttributeCerts.IsTrue;

		/**
		 * @return Returns the distributionPoint.
		 */
		public DistributionPointName DistributionPoint => m_distributionPoint;

		/**
		 * @return Returns the onlySomeReasons.
		 */
		public ReasonFlags OnlySomeReasons => m_onlySomeReasons;

		public override Asn1Object ToAsn1Object() => m_seq;

		public override string ToString()
		{
			StringBuilder buf = new StringBuilder();
			buf.AppendLine("IssuingDistributionPoint: [");
			if (m_distributionPoint != null)
			{
				AppendObject(buf, "distributionPoint", m_distributionPoint.ToString());
			}
			if (m_onlyContainsUserCerts.IsTrue)
			{
				AppendObject(buf, "onlyContainsUserCerts", m_onlyContainsUserCerts.ToString());
			}
			if (m_onlyContainsCACerts.IsTrue)
			{
				AppendObject(buf, "onlyContainsCACerts", m_onlyContainsCACerts.ToString());
			}
			if (m_onlySomeReasons != null)
			{
				AppendObject(buf, "onlySomeReasons", m_onlySomeReasons.ToString());
			}
			if (m_onlyContainsAttributeCerts.IsTrue)
			{
				AppendObject(buf, "onlyContainsAttributeCerts", m_onlyContainsAttributeCerts.ToString());
			}
			if (m_indirectCRL.IsTrue)
			{
				AppendObject(buf, "indirectCRL", m_indirectCRL.ToString());
			}
			buf.AppendLine("]");
			return buf.ToString();
		}

		private void AppendObject(StringBuilder buf, string name, string val)
		{
			string indent = "    ";
			buf.Append(indent);
			buf.Append(name);
			buf.AppendLine(":");
			buf.Append(indent);
			buf.Append(indent);
			buf.Append(val);
			buf.AppendLine();
		}
	}
}
