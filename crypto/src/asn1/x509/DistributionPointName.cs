using System;
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

        public static DistributionPointName GetInstance(object obj) =>
            Asn1Utilities.GetInstanceChoice(obj, GetOptional);

        public static DistributionPointName GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            Asn1Utilities.GetInstanceChoice(obj, explicitly, GetInstance);

        public static DistributionPointName GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is DistributionPointName distributionPointName)
                return distributionPointName;

            Asn1TaggedObject taggedObject = Asn1TaggedObject.GetOptional(element);
            if (taggedObject != null)
            {
                Asn1Encodable baseObject = GetOptionalBaseObject(taggedObject);
                if (baseObject != null)
                    return new DistributionPointName(taggedObject.TagNo, baseObject);
            }

            return null;
        }

        public static DistributionPointName GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            Asn1Utilities.GetTaggedChoice(taggedObject, declaredExplicit, GetInstance);

        private static Asn1Encodable GetOptionalBaseObject(Asn1TaggedObject taggedObject)
        {
            if (taggedObject.HasContextTag())
            {
                switch (taggedObject.TagNo)
                {
                case FullName:
                    return GeneralNames.GetTagged(taggedObject, false);
                case NameRelativeToCrlIssuer:
                    return Asn1Set.GetTagged(taggedObject, false);
                }
            }
            return null;
        }

        private readonly int m_type;
        private readonly Asn1Encodable m_name;

        public DistributionPointName(GeneralNames name)
            : this(FullName, name)
        {
        }

        public DistributionPointName(int type, Asn1Encodable name)
        {
            m_type = type;
            m_name = name;
        }

        [Obsolete("Use 'Type' instead")]
        public int PointType => m_type;

        public Asn1Encodable Name => m_name;

        public int Type => m_type;

        public override Asn1Object ToAsn1Object() => new DerTaggedObject(false, m_type, m_name);

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
