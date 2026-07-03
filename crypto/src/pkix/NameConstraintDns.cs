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
                if (Platform.EqualsIgnoreCase(dns.m_value, constraint.m_value)
                    || NameConstraintUtilities.WithinDomain(dns.m_value, constraint.m_value))
                {
                    return true;
                }
            }

            return false;
        }

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
                    // dns is the intersection at most once (the narrower of an overlapping pair), so once it
                    // is known to be added the WithinDomain subsumption test that gates it is skipped.
                    bool addDns = false;
                    foreach (var _permitted in permitted)
                    {
                        if (Platform.EqualsIgnoreCase(_permitted.m_value, dns.m_value)
                            || NameConstraintUtilities.WithinDomain(_permitted.m_value, dns.m_value))
                        {
                            // dns subsumes _permitted: the intersection is the narrower _permitted.
                            intersect.Add(_permitted);
                        }
                        else
                        {
                            addDns = addDns || NameConstraintUtilities.WithinDomain(dns.m_value, _permitted.m_value);
                        }
                    }
                    if (addDns)
                    {
                        // _permitted subsumes dns: the intersection is the narrower dns.
                        intersect.Add(dns);
                    }
                }
            }
            return intersect;
        }

        internal static HashSet<NameConstraintDns> Union(HashSet<NameConstraintDns> excluded, NameConstraintDns dns)
        {
            if (excluded == null)
                return new HashSet<NameConstraintDns> { dns };

            // Union with each existing constraint: drop any _excluded that dns subsumes, keep the rest, and
            // add dns itself unless some _excluded subsumes it. dns is added at most once (at the end), and
            // once it is known to be added the WithinDomain subsumption test is skipped (the || short-circuits).
            var union = new HashSet<NameConstraintDns>();
            bool addDns = false;
            foreach (var _excluded in excluded)
            {
                if (Platform.EqualsIgnoreCase(_excluded.m_value, dns.m_value)
                    || NameConstraintUtilities.WithinDomain(_excluded.m_value, dns.m_value))
                {
                    // dns subsumes _excluded, so _excluded is dropped and dns will represent it.
                    addDns = true;
                }
                else
                {
                    union.Add(_excluded);

                    addDns = addDns || !NameConstraintUtilities.WithinDomain(dns.m_value, _excluded.m_value);
                }
            }
            if (addDns)
            {
                union.Add(dns);
            }
            return union;
        }
    }
}
