using System;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    public class GeneralNames
		: Asn1Encodable
	{
        public static GeneralNames GetInstance(object obj)
		{
            if (obj == null)
                return null;
            if (obj is GeneralNames generalNames)
                return generalNames;
            return new GeneralNames(Asn1Sequence.GetInstance(obj));
		}

		public static GeneralNames GetInstance(Asn1TaggedObject obj, bool explicitly) =>
			new GeneralNames(Asn1Sequence.GetInstance(obj, explicitly));

        public static GeneralNames GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GeneralNames(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static GeneralNames FromExtensions(X509Extensions extensions, DerObjectIdentifier extOid)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, extOid));
        }

        private readonly GeneralName[] m_names;

        /// <summary>Construct a GeneralNames object containing one GeneralName.</summary>
		/// <param name="name">The name to be contained.</param>
		public GeneralNames(GeneralName name)
		{
			m_names = new GeneralName[]{
				name ?? throw new ArgumentNullException(nameof(name))
			};
		}

        public GeneralNames(GeneralName[] names)
        {
			if (Arrays.IsNullOrContainsNull(names))
                throw new NullReferenceException("'names' cannot be null, or contain null");

            m_names = Copy(names);
        }

		private GeneralNames(Asn1Sequence seq)
		{
			m_names = seq.MapElements(GeneralName.GetInstance);
		}

		public int Count => m_names.Length;

		public GeneralName[] GetNames() => Copy(m_names);

		/**
		 * Produce an object suitable for an Asn1OutputStream.
		 * <pre>
		 * GeneralNames ::= Sequence SIZE {1..MAX} OF GeneralName
		 * </pre>
		 */
		public override Asn1Object ToAsn1Object() => DerSequence.FromElements(m_names);

		public override string ToString()
		{
			StringBuilder buf = new StringBuilder();
			buf.AppendLine("GeneralNames:");
			foreach (GeneralName name in m_names)
			{
				buf.Append("    ")
				   .Append(name)
				   .AppendLine();
			}
			return buf.ToString();
		}

        private static GeneralName[] Copy(GeneralName[] names) => (GeneralName[])names.Clone();
    }
}
