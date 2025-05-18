using System;
using System.Text;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The DistributionPoint object.
     * <pre>
     * DistributionPoint ::= Sequence {
     *      distributionPoint [0] DistributionPointName OPTIONAL,
     *      reasons           [1] ReasonFlags OPTIONAL,
     *      cRLIssuer         [2] GeneralNames OPTIONAL
     * }
     * </pre>
     */
    public class DistributionPoint
        : Asn1Encodable
    {
		public static DistributionPoint GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DistributionPoint distributionPoint)
                return distributionPoint;
            return new DistributionPoint(Asn1Sequence.GetInstance(obj));
        }

        public static DistributionPoint GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new DistributionPoint(Asn1Sequence.GetInstance(obj, explicitly));

        public static DistributionPoint GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new DistributionPoint(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly DistributionPointName m_distributionPoint;
        private readonly ReasonFlags m_reasons;
        private readonly GeneralNames m_crlIssuer;

        private DistributionPoint(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 0 || count > 3)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

            m_distributionPoint = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, true,
                DistributionPointName.GetTagged); // CHOICE
            m_reasons = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 1, false,
                (t, e) => new ReasonFlags(DerBitString.GetTagged(t, e)));
            m_crlIssuer = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 2, false, GeneralNames.GetTagged);

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));
        }

        public DistributionPoint(DistributionPointName distributionPointName, ReasonFlags reasons,
            GeneralNames crlIssuer)
        {
            m_distributionPoint = distributionPointName;
            m_reasons = reasons;
            m_crlIssuer = crlIssuer;
        }

        public DistributionPointName DistributionPointName => m_distributionPoint;

		public ReasonFlags Reasons => m_reasons;

		public GeneralNames CrlIssuer => m_crlIssuer;

        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(3);
            v.AddOptionalTagged(true, 0, m_distributionPoint); // CHOICE
            v.AddOptionalTagged(false, 1, m_reasons);
            v.AddOptionalTagged(false, 2, m_crlIssuer);
            return new DerSequence(v);
        }

		public override string ToString()
		{
			StringBuilder buf = new StringBuilder();
			buf.AppendLine("DistributionPoint: [");
			if (m_distributionPoint != null)
			{
                AppendObject(buf, "distributionPoint", m_distributionPoint.ToString());
			}
			if (m_reasons != null)
			{
                AppendObject(buf, "reasons", m_reasons.ToString());
			}
			if (m_crlIssuer != null)
			{
                AppendObject(buf, "cRLIssuer", m_crlIssuer.ToString());
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
