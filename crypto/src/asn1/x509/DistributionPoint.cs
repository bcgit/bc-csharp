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

        public static DistributionPoint GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return GetInstance(Asn1Sequence.GetInstance(obj, explicitly));
        }

        private readonly DistributionPointName m_distributionPoint;
        private readonly ReasonFlags m_reasons;
        private readonly GeneralNames m_crlIssuer;

        private DistributionPoint(Asn1Sequence seq)
        {
            for (int i = 0; i != seq.Count; i++)
            {
				Asn1TaggedObject t = Asn1TaggedObject.GetInstance(seq[i]);

				switch (t.TagNo)
                {
                case 0:
                    m_distributionPoint = DistributionPointName.GetInstance(t, true);
                    break;
                case 1:
                    m_reasons = new ReasonFlags(DerBitString.GetInstance(t, false));
                    break;
                case 2:
                    m_crlIssuer = GeneralNames.GetInstance(t, false);
                    break;
                }
            }
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

            // As this is a CHOICE it must be explicitly tagged
            v.AddOptionalTagged(true, 0, m_distributionPoint);

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
