using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>An rfc822Name (tested name or constraint) in canonical form for name-constraint processing.</summary>
    /// <remarks>
    /// Construction is the only way in: the RFC 1034 root-label trailing dot (of the host, which is always the
    /// string tail) is stripped once, here, and the value's shape - particular mailbox ("local@host"), legacy
    /// exact-host ("@host"), host ("host") or domain (".domain") - is classified once, here, into a
    /// <see cref="NameConstraintKind"/>, with the host comparand cached alongside. The canonical string remains
    /// the identity: equality and hashing are case-insensitive on it alone (kind and host are derived from it),
    /// and original case is preserved for display. A tested name classifies through the same rules; matching
    /// only ever branches on the constraint's kind.
    /// </remarks>
    internal readonly struct NameConstraintEmail
        : IEquatable<NameConstraintEmail>, INameConstraintHostName
    {
        internal static NameConstraintEmail Create(string email) =>
            new NameConstraintEmail(NameConstraintUtilities.StripTrailingDot(email));

        private readonly NameConstraintKind m_kind;
        private readonly string m_value;
        private readonly string m_host;

        private NameConstraintEmail(string value)
        {
            // Classification follows RFC 5280 4.2.1.10, which defines three rfc822Name constraint forms:
            // a particular mailbox ("local@host"), a host ("host") and a domain (".domain"). Known
            // deviations, deliberately retained (shared with bc-java; revisit only as separate decisions):
            // - "@host" (AtHost) is a legacy exact-host form not in RFC 5280; OpenSSL also honours it.
            // - The mailbox host is split at the FIRST '@', but a quoted local part may legally contain
            //   '@' (RFC 2821 4.1.2 Quoted-string), making the LAST '@' the grammar-correct split.
            //   OpenSSL shares the first-'@' reading, so this is the de-facto ecosystem behaviour.
            // - Mailbox matching (see IsConstrained) compares the whole address ignoring case, but
            //   RFC 5280 7.5 wants a case-SENSITIVE local part. Spec-correcting it would match fewer
            //   names, i.e. fail-open for excluded subtrees - the current over-match is the safer error.
            int atPos = value.IndexOf('@');

            m_value = value;
            if (atPos > 0)
            {
                m_kind = NameConstraintKind.Mailbox;
                m_host = value.Substring(atPos + 1);
            }
            else if (Platform.StartsWith(value, "."))
            {
                // No overlap with AtHost: a value with '@' at index 0 cannot start with '.'.
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
                // Last chance: the legacy "@host" form ('@' at index 0).
                m_kind = NameConstraintKind.AtHost;
                m_host = value.Substring(1);
            }
        }

        NameConstraintKind INameConstraintHostName.Kind => m_kind;

        string INameConstraintHostName.Value => m_value;

        string INameConstraintHostName.Host => m_host;

        public bool Equals(NameConstraintEmail other) => Platform.EqualsIgnoreCase(m_value, other.m_value);

        public override bool Equals(object obj) => obj is NameConstraintEmail other && Equals(other);

        public override int GetHashCode() =>
            m_value == null ? 0 : StringComparer.OrdinalIgnoreCase.GetHashCode(m_value);

        public override string ToString() => m_value;

        internal static bool IsConstrained(HashSet<NameConstraintEmail> constraints, NameConstraintEmail email)
        {
            foreach (var constraint in constraints)
            {
                if (IsConstrained(constraint, email))
                    return true;
            }

            return false;
        }

        private static bool IsConstrained(NameConstraintEmail constraint, NameConstraintEmail email)
        {
            switch (constraint.m_kind)
            {
            // a particular mailbox
            case NameConstraintKind.Mailbox:
                return Platform.EqualsIgnoreCase(email.m_value, constraint.m_value);
            // "@domain" style
            case NameConstraintKind.AtHost:
                return Platform.EqualsIgnoreCase(email.m_host, constraint.m_host);
            // address in sub domain
            case NameConstraintKind.Domain:
                return NameConstraintUtilities.WithinDomain(email.m_host, constraint.m_value);
            // on particular host
            default:
                return Platform.EqualsIgnoreCase(email.m_host, constraint.m_value);
            }
        }

        internal static HashSet<NameConstraintEmail> Intersect(HashSet<NameConstraintEmail> permitted,
            HashSet<GeneralSubtree> subtrees)
        {
            var intersect = new HashSet<NameConstraintEmail>();
            foreach (GeneralSubtree subtree in subtrees)
            {
                var email = Create(NameConstraintUtilities.ExtractIA5String(subtree));

                if (permitted == null)
                {
                    intersect.Add(email);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        NameConstraintUtilities.Intersect(email, _permitted, intersect);
                    }
                }
            }
            return intersect;
        }

        internal static HashSet<NameConstraintEmail> Union(HashSet<NameConstraintEmail> excluded,
            NameConstraintEmail email)
        {
            if (excluded == null)
                return new HashSet<NameConstraintEmail> { email };

            var union = new HashSet<NameConstraintEmail>();
            foreach (var _excluded in excluded)
            {
                NameConstraintUtilities.Union(_excluded, email, union);
            }
            return union;
        }
    }
}
