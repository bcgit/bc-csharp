using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    public class CrlDistPoint
        : Asn1Encodable
    {
        public static CrlDistPoint GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlDistPoint crlDistPoint)
                return crlDistPoint;
            return new CrlDistPoint(Asn1Sequence.GetInstance(obj));
        }

        public static CrlDistPoint GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new CrlDistPoint(Asn1Sequence.GetInstance(obj, explicitly));

        public static CrlDistPoint GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlDistPoint(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static CrlDistPoint FromExtensions(X509Extensions extensions)
        {
            return GetInstance(
                X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.CrlDistributionPoints));
        }

        private readonly Asn1Sequence m_seq;

        private CrlDistPoint(Asn1Sequence seq)
        {
            m_seq = seq;
        }

		public CrlDistPoint(DistributionPoint[] points)
        {
			m_seq = new DerSequence(points);
        }

        /**
         * Return the distribution points making up the sequence.
         *
         * @return DistributionPoint[]
         */
        public DistributionPoint[] GetDistributionPoints() => m_seq.MapElements(DistributionPoint.GetInstance);

        /**
         * Produce an object suitable for an Asn1OutputStream.
         * <pre>
         * CrlDistPoint ::= Sequence SIZE {1..MAX} OF DistributionPoint
         * </pre>
         */
        public override Asn1Object ToAsn1Object() => m_seq;

		public override string ToString()
		{
			StringBuilder buf = new StringBuilder();
			buf.AppendLine("CRLDistPoint:");
            foreach (DistributionPoint dp in GetDistributionPoints())
			{
				buf.Append("    ")
				   .Append(dp)
                   .AppendLine();
			}
			return buf.ToString();
		}
	}
}
