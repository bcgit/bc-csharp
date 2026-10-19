using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <summary>The GeneralNames structure of RFC 5280: a sequence of GeneralName.</summary>
    public class GeneralNames
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="GeneralNames"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="GeneralNames"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="GeneralNames"/>, or null if <paramref name="obj"/> is null.</returns>
        public static GeneralNames GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is GeneralNames generalNames)
                return generalNames;
            return new GeneralNames(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="GeneralNames"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GeneralNames"/>.</returns>
        public static GeneralNames GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new GeneralNames(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="GeneralNames"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>The <see cref="GeneralNames"/>, or null if <paramref name="element"/> is null.</returns>
        public static GeneralNames GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is GeneralNames generalNames)
                return generalNames;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new GeneralNames(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="GeneralNames"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="GeneralNames"/>.</returns>
        public static GeneralNames GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new GeneralNames(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static GeneralNames FromExtensions(X509Extensions extensions, DerObjectIdentifier extOid) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, extOid));

        private readonly GeneralName[] m_names;

        /// <summary>Construct a GeneralNames object containing one GeneralName.</summary>
        /// <param name="name">The name to be contained.</param>
        public GeneralNames(GeneralName name)
        {
            m_names = new GeneralName[]{
                name ?? throw new ArgumentNullException(nameof(name))
            };
        }

        /// <summary>Create a new <see cref="GeneralNames"/>.</summary>
        /// <param name="names">The names.</param>
        public GeneralNames(GeneralName[] names)
        {
            if (Arrays.IsNullOrContainsNull(names))
                throw new ArgumentNullException(nameof(names), "cannot be null, or contain null");

            m_names = Copy(names);
        }

        private GeneralNames(Asn1Sequence seq)
        {
            m_names = seq.MapElements(GeneralName.GetInstance);
        }

        /// <summary>Gets the count.</summary>
        public int Count => m_names.Length;

        /// <summary>Return the names.</summary>
        public GeneralName[] GetNames() => Copy(m_names);

        /// <summary>Produce an object suitable for an Asn1OutputStream.</summary>
        /// <remarks>
        /// <code>
        /// GeneralNames ::= Sequence SIZE {1..MAX} OF GeneralName
        /// </code>
        /// </remarks>
        public override Asn1Object ToAsn1Object() => DerSequence.FromElements(m_names);

        /// <inheritdoc/>
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
