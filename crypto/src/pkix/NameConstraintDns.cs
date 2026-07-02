using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>A dNSName (tested name or constraint) in canonical form for name-constraint processing.</summary>
    /// <remarks>
    /// Construction is the only way in: the RFC 1034 root-label trailing dot is stripped once, here, so every
    /// downstream comparison and set operation works on canonical values by construction. Equality and hashing
    /// are case-insensitive (original case is preserved for display). A constraint value may carry a leading
    /// dot, restricting it to proper subdomains.
    /// </remarks>
    internal readonly struct NameConstraintDns
        : IEquatable<NameConstraintDns>
    {
        internal static NameConstraintDns Create(string dns) =>
            new NameConstraintDns(NameConstraintUtilities.StripTrailingDot(dns));

        private readonly string m_value;

        private NameConstraintDns(string value)
        {
            m_value = value;
        }

        public bool Equals(NameConstraintDns other) => Platform.EqualsIgnoreCase(m_value, other.m_value);

        public override bool Equals(object obj) => obj is NameConstraintDns other && Equals(other);

        public override int GetHashCode() =>
            m_value == null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(m_value);

        public override string ToString() => m_value;

        internal static bool IsConstrained(HashSet<NameConstraintDns> constraints, NameConstraintDns dns)
        {
            foreach (var constraint in constraints)
            {
                if (IsConstrained(constraint, dns))
                    return true;
            }

            return false;
        }

        private static bool IsConstrained(NameConstraintDns constraint, NameConstraintDns dns) =>
            NameConstraintUtilities.IsDnsMatch(constraint.m_value, dns.m_value);

        internal static HashSet<NameConstraintDns> Intersect(HashSet<NameConstraintDns> permitted,
            HashSet<GeneralSubtree> subtrees)
        {
            var intersect = new HashSet<NameConstraintDns>();
            foreach (GeneralSubtree subtree in subtrees)
            {
                var dns = Create(NameConstraintUtilities.ExtractIA5String(subtree));

                if (permitted == null)
                {
                    intersect.Add(dns);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        if (IsConstrained(dns, _permitted))
                        {
                            intersect.Add(_permitted);
                        }
                        else if (NameConstraintUtilities.WithinDomain(dns.m_value, _permitted.m_value))
                        {
                            intersect.Add(dns);
                        }
                        else
                        {
                            // No intersection
                        }
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
                if (IsConstrained(dns, _excluded))
                {
                    union.Add(dns);
                }
                else if (NameConstraintUtilities.WithinDomain(dns.m_value, _excluded.m_value))
                {
                    union.Add(_excluded);
                }
                else
                {
                    union.Add(_excluded);
                    union.Add(dns);
                }
            }
            return union;
        }
    }
}
