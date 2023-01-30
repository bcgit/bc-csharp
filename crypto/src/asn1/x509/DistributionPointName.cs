using System.Text;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The DistributionPointName object.
     * <pre>
     * DistributionPointName ::= CHOICE {
     *     fullName                 [0] GeneralNames,
     *     nameRelativeToCRLIssuer  [1] RDN
     * }
     * </pre>
     */
    public class DistributionPointName
        : Asn1Encodable, IAsn1Choice
    {
        public const int FullName = 0;
        public const int NameRelativeToCrlIssuer = 1;

		public static DistributionPointName GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is DistributionPointName distributionPointName)
                return distributionPointName;
            return new DistributionPointName(Asn1TaggedObject.GetInstance(obj));
		}

		public static DistributionPointName GetInstance(Asn1TaggedObject obj, bool explicitly)
        {
            return GetInstance(Asn1TaggedObject.GetInstance(obj, true));
        }

        private readonly Asn1Encodable m_name;
        private readonly int m_type;

        public DistributionPointName(GeneralNames name)
            : this(FullName, name)
        {
        }

        public DistributionPointName(int type, Asn1Encodable name)
        {
            m_type = type;
            m_name = name;
        }

		public int PointType => m_type;

		public Asn1Encodable Name => m_name;

		public DistributionPointName(Asn1TaggedObject obj)
        {
            m_type = obj.TagNo;

			if (m_type == FullName)
            {
                m_name = GeneralNames.GetInstance(obj, false);
            }
            else
            {
                m_name = Asn1Set.GetInstance(obj, false);
            }
        }

		public override Asn1Object ToAsn1Object()
        {
            return new DerTaggedObject(false, m_type, m_name);
        }

		public override string ToString()
		{
			StringBuilder buf = new StringBuilder();
			buf.AppendLine("DistributionPointName: [");
			if (m_type == FullName)
			{
				AppendObject(buf, "fullName", m_name.ToString());
			}
			else
			{
				AppendObject(buf, "nameRelativeToCRLIssuer", m_name.ToString());
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
