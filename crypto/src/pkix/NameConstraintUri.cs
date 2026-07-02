using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>
    /// A uniformResourceIdentifier (tested name or constraint) in canonical form for name-constraint
    /// processing.
    /// </summary>
    /// <remarks>
    /// Construction is the only way in. A tested name is reduced to its RFC 3986 authority host (via
    /// <see cref="NameConstraintUtilities.ExtractHostFromURL"/>) with the RFC 1034 root-label trailing dot
    /// stripped; a constraint (a host, or a ".domain") is stripped of a trailing dot only. The value's shape
    /// is classified once, here, into a <see cref="NameConstraintKind"/> with the same precedence as
    /// <see cref="NameConstraintEmail"/>, because the subtree intersect/union logic is a historical clone of
    /// the rfc822Name logic - including its '@' dispatch, which never fires for well-formed URI constraints -
    /// and is deliberately kept branch-for-branch identical (on canonical values). The canonical string
    /// remains the identity: equality and hashing are case-insensitive on it alone (kind and host are derived
    /// from it), and original case is preserved for display.
    /// </remarks>
    internal readonly struct NameConstraintUri
        : IEquatable<NameConstraintUri>, INameConstraintHostName
    {
        internal static NameConstraintUri FromConstraint(string constraint) =>
            new NameConstraintUri(NameConstraintUtilities.StripTrailingDot(constraint));

        internal static NameConstraintUri FromUri(string uri) =>
            new NameConstraintUri(NameConstraintUtilities.StripTrailingDot(
                NameConstraintUtilities.ExtractHostFromURL(uri)));

        private readonly NameConstraintKind m_kind;
        private readonly string m_value;
        private readonly string m_host;

        private NameConstraintUri(string value)
        {
            // Classified with the same precedence as NameConstraintEmail so that the set algebra keeps its
            // exact branch structure. Matching (IsConstrained) treats every non-Domain kind as a host,
            // comparing against the whole canonical value, which keeps the '@' forms inert there.
            int atPos = value.IndexOf('@');

            m_value = value;
            if (atPos > 0)
            {
                m_kind = NameConstraintKind.Mailbox;
                m_host = value.Substring(atPos + 1);
            }
            else if (Platform.StartsWith(value, "."))
            {
                m_kind = NameConstraintKind.Domain;
                m_host = value;
            }
            else if (atPos < 0)
            {
                m_kind = NameConstraintKind.Host;
                m_host = value;
            }
            else
            {
                m_kind = NameConstraintKind.AtHost;
                m_host = value.Substring(1);
            }
        }

        NameConstraintKind INameConstraintHostName.Kind => m_kind;

        string INameConstraintHostName.Value => m_value;

        string INameConstraintHostName.Host => m_host;

        public bool Equals(NameConstraintUri other) => Platform.EqualsIgnoreCase(m_value, other.m_value);

        public override bool Equals(object obj) => obj is NameConstraintUri other && Equals(other);

        public override int GetHashCode() =>
            m_value == null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(m_value);

        public override string ToString() => m_value;

        internal static bool IsConstrained(HashSet<NameConstraintUri> constraints, NameConstraintUri host)
        {
            foreach (var constraint in constraints)
            {
                if (IsConstrained(constraint, host))
                    return true;
            }

            return false;
        }

        private static bool IsConstrained(NameConstraintUri constraint, NameConstraintUri host)
        {
            // in sub domain or domain
            if (constraint.m_kind == NameConstraintKind.Domain)
                return NameConstraintUtilities.WithinDomain(host.m_value, constraint.m_value);

            // a host (an extracted host cannot contain '@', so Mailbox/AtHost forms never match here)
            return Platform.EqualsIgnoreCase(host.m_value, constraint.m_value);
        }

        internal static HashSet<NameConstraintUri> Intersect(HashSet<NameConstraintUri> permitted,
            HashSet<GeneralSubtree> subtrees)
        {
            var intersect = new HashSet<NameConstraintUri>();
            foreach (GeneralSubtree subtree in subtrees)
            {
                var uri = FromConstraint(NameConstraintUtilities.ExtractIA5String(subtree));

                if (permitted == null)
                {
                    intersect.Add(uri);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        // NOTE: historically mirrored operand order relative to the rfc822Name family.
                        NameConstraintUtilities.Intersect(_permitted, uri, intersect);
                    }
                }
            }
            return intersect;
        }

        internal static HashSet<NameConstraintUri> Union(HashSet<NameConstraintUri> excluded, NameConstraintUri uri)
        {
            if (excluded == null)
                return new HashSet<NameConstraintUri> { uri };

            var union = new HashSet<NameConstraintUri>();
            foreach (var _excluded in excluded)
            {
                NameConstraintUtilities.Union(_excluded, uri, union);
            }
            return union;
        }
    }
}
