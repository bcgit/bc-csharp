using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

using static Org.BouncyCastle.Pkix.NameConstraintRelation;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>A dNSName (tested name or constraint) in canonical form for name-constraint processing.</summary>
    /// <remarks>
    /// Construction is the only way in, and it validates as well as canonicalises: an empty label is
    /// rejected and the single RFC 1034 root-label trailing dot is stripped, so every downstream comparison
    /// and set operation works on validated, canonical values by construction. A constraint may carry a
    /// leading dot, excluding the apex from the subtree - the de facto reading shared by OpenSSL, Go and
    /// bc-java, alongside RFC 5280 sec. 4.2.1.10's own undotted, apex-inclusive form. A tested name may
    /// not: there the leading dot is just an empty first label. Equality and hashing are case-insensitive
    /// (original case is preserved for display). Matching and the subtree set algebra go through the shared
    /// <c>Relate</c> classifier with one fixed <see cref="NameConstraintHostNameKind.Domain"/> kind: both
    /// spellings denote subtrees, and RelateDomains reads the apex distinction from the value itself.
    /// </remarks>
    internal readonly struct NameConstraintDns
        : IEquatable<NameConstraintDns>, INameConstraintHostName
    {
        /// <exception cref="PkixNameConstraintValidatorException">for an empty label</exception>
        internal static NameConstraintDns FromConstraint(string constraint) =>
            new NameConstraintDns(NameConstraintUtilities.StripTrailingDot(constraint), isConstraint: true);

        /// <exception cref="PkixNameConstraintValidatorException">for an empty label, or a leading dot
        /// (the proper-subtree form is a constraint-only shape)</exception>
        internal static NameConstraintDns FromName(string name) =>
            new NameConstraintDns(NameConstraintUtilities.StripTrailingDot(name), isConstraint: false);

        private readonly string m_value;

        private NameConstraintDns(string value, bool isConstraint)
        {
            m_value = value;

            // A constraint may carry the proper-subtree leading dot; a tested name may not, so its leading
            // dot is validated as part of the host - and rejected as an empty first label.
            int hostStart = isConstraint && Platform.StartsWith(value, ".") ? 1 : 0;
            NameConstraintUtilities.CheckHostLabels(value, hostStart, "dNSName");
        }

        // Every dNSName denotes a subtree, so the shared algebra sees one fixed kind: apex-inclusive when
        // plain, apex-exclusive with the constraint-only leading dot - a distinction RelateDomains reads
        // from the value itself.
        NameConstraintHostNameKind INameConstraintHostName.Kind => NameConstraintHostNameKind.Domain;

        string INameConstraintHostName.Value => m_value;

        string INameConstraintHostName.Host => m_value;

        public bool Equals(NameConstraintDns other) => Platform.EqualsIgnoreCase(m_value, other.m_value);

        public override bool Equals(object obj) => obj is NameConstraintDns other && Equals(other);

        public override int GetHashCode() =>
            m_value == null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(m_value);

        public override string ToString() => m_value;

        internal static bool IsConstrained(HashSet<NameConstraintDns> constraints, NameConstraintDns dns)
        {
            foreach (var constraint in constraints)
            {
                var relation = dns.Relate(constraint);
                if (relation == Equal || relation == SubsumedBy)
                    return true;
            }

            return false;
        }

        internal static HashSet<NameConstraintDns> Intersect(HashSet<NameConstraintDns> permitted,
            HashSet<GeneralSubtree> subtrees)
        {
            var intersect = new HashSet<NameConstraintDns>();
            foreach (GeneralSubtree subtree in subtrees)
            {
                var dns = FromConstraint(NameConstraintUtilities.ExtractIA5String(subtree));

                if (permitted == null)
                {
                    intersect.Add(dns);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        // Existing constraint first: an equal pair keeps the first-registered instance.
                        NameConstraintUtilities.Intersect(_permitted, dns, intersect);
                    }
                }
            }
            return intersect;
        }

        internal static HashSet<NameConstraintDns> Union(HashSet<NameConstraintDns> excluded, NameConstraintDns dns)
        {
            if (excluded == null)
                return new HashSet<NameConstraintDns> { dns };

            var union = new HashSet<NameConstraintDns>();
            foreach (var _excluded in excluded)
            {
                // Existing constraint first: an equal pair keeps the first-registered instance.
                NameConstraintUtilities.Union(_excluded, dns, union);
            }
            return union;
        }
    }
}
