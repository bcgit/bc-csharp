using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /// <remarks><code>CrlDistPoint ::= SEQUENCE SIZE {1..MAX} OF DistributionPoint</code></remarks>
    public class CrlDistPoint
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="CrlDistPoint"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="CrlDistPoint"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="CrlDistPoint"/>, or null if <paramref name="obj"/> is null.</returns>
        public static CrlDistPoint GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is CrlDistPoint crlDistPoint)
                return crlDistPoint;
            return new CrlDistPoint(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="CrlDistPoint"/> from a tagged object.</summary>
        /// <param name="obj">The tagged object.</param>
        /// <param name="explicitly">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlDistPoint"/>.</returns>
        public static CrlDistPoint GetInstance(Asn1TaggedObject obj, bool explicitly) =>
            new CrlDistPoint(Asn1Sequence.GetInstance(obj, explicitly));

        /// <summary>Return an <see cref="CrlDistPoint"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="CrlDistPoint"/>.</returns>
        public static CrlDistPoint GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new CrlDistPoint(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /// <summary>Get the extension of this type from a table of extensions, if it is present.</summary>
        /// <param name="extensions">The extensions, or null.</param>
        /// <returns>The value, or null if the extension is not present.</returns>
        public static CrlDistPoint FromExtensions(X509Extensions extensions) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.CrlDistributionPoints));

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_elements;

        private CrlDistPoint(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            m_elements = DerSequence.Map(seq, DistributionPoint.GetInstance);
        }

        /// <summary>Construct an instance containing a single <see cref="DistributionPoint"/>.</summary>
        public CrlDistPoint(DistributionPoint element)
        {
            m_elements = DerSequence.FromElement(element ?? throw new ArgumentNullException(nameof(element)));
        }

        /// <summary>Create a new <see cref="CrlDistPoint"/>.</summary>
        /// <param name="points">The points.</param>
        public CrlDistPoint(DistributionPoint[] points)
        {
            if (Arrays.IsNullOrContainsNull(points))
                throw new ArgumentNullException(nameof(points), "cannot be null, or contain null");
            if (points.Length < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(points));

            m_elements = DerSequence.FromElements(points);
        }

        /// <summary>Return the <see cref="DistributionPoint"/>s making up the sequence.</summary>
        public DistributionPoint[] GetDistributionPoints() => m_elements.MapElements(DistributionPoint.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_elements;

        /// <inheritdoc/>
        public override string ToString()
        {
            StringBuilder buf = new StringBuilder();
            buf.AppendLine("CRLDistPoint:");
            // Elements are known to be DistributionPoint by construction
            foreach (DistributionPoint dp in m_elements)
            {
                buf.Append("    ")
                   .Append(dp)
                   .AppendLine();
            }
            return buf.ToString();
        }
    }
}
