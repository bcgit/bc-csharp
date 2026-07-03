using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>An rfc822Name (tested name or constraint) in canonical form for name-constraint processing.</summary>
    /// <remarks>
    /// Construction is the only way in, and it validates as well as canonicalises: the single RFC 1034
    /// root-label trailing dot (of the host, which is always the string tail) is stripped once, here; the
    /// value's shape - particular mailbox ("local@host"), legacy exact-host ("@host"), host ("host") or
    /// domain (".domain") - is classified once, here, into a <see cref="NameConstraintHostNameKind"/>, with
    /// the host comparand cached alongside; and the host part is then rejected if it contains an empty label
    /// (fail-closed). The domain form's leading dot is a constraint-only shape, so a tested name (which
    /// classifies through the same rules) is rejected for it too; the mailbox LOCAL part is not restricted
    /// (a quoted local part may legally contain dots). The canonical string remains the identity: equality
    /// and hashing are case-insensitive on it alone (kind and host are derived from it), and original case
    /// is preserved for display. Matching only ever branches on the constraint's kind.
    /// </remarks>
    internal readonly struct NameConstraintEmail
        : IEquatable<NameConstraintEmail>, INameConstraintHostName
    {
        /// <exception cref="PkixNameConstraintValidatorException">for an empty label in the host</exception>
        internal static NameConstraintEmail FromConstraint(string constraint) =>
            new NameConstraintEmail(NameConstraintUtilities.StripTrailingDot(constraint), isConstraint: true);

        /// <exception cref="PkixNameConstraintValidatorException">for an empty label in the host, or a
        /// leading dot (the domain form is a constraint-only shape)</exception>
        internal static NameConstraintEmail FromAddress(string address) =>
            new NameConstraintEmail(NameConstraintUtilities.StripTrailingDot(address), isConstraint: false);

        private readonly NameConstraintHostNameKind m_kind;
        private readonly string m_value;
        private readonly string m_host;

        private NameConstraintEmail(string value, bool isConstraint)
        {
            // Classification follows RFC 5280 4.2.1.10, which defines three rfc822Name constraint forms:
            // a particular mailbox ("local@host"), a host ("host") and a domain (".domain"). Known
            // deviations, deliberately retained (shared with bc-java; revisit only as separate decisions):
            // - "@host" (AtHost) is a legacy exact-host form not in RFC 5280; OpenSSL also honours it.
            // - The mailbox host is split at the FIRST '@', which is unambiguous only for a single-'@'
            //   value: a quoted local part may legally contain '@' (RFC 2821 4.1.2 Quoted-string), making
            //   the LAST '@' the grammar-correct split. Tested names with more than one '@' are rejected
            //   upstream (see PkixNameConstraintValidator.CheckEmail), so the first-'@' split only runs on
            //   unambiguous tested names; a constraint may still carry a quoted '@' but is matched by
            //   whole-string equality, so its split position is immaterial. OpenSSL also splits at first-'@'.
            // - Mailbox matching (see IsConstrained) compares the whole address ignoring case, but
            //   RFC 5280 7.5 wants a case-SENSITIVE local part. Spec-correcting it would match fewer
            //   names, i.e. fail-open for excluded subtrees - the current over-match is the safer error.
            int atPos = value.IndexOf('@');

            m_value = value;
            if (atPos > 0)
            {
                m_kind = NameConstraintHostNameKind.Mailbox;
                m_host = value.Substring(atPos + 1);
            }
            else if (Platform.StartsWith(value, "."))
            {
                // No overlap with AtHost: a value with '@' at index 0 cannot start with '.'.
                m_kind = NameConstraintHostNameKind.Domain;
                m_host = value;
            }
            else if (atPos < 0)
            {
                m_kind = NameConstraintHostNameKind.Host;
                m_host = value;
            }
            else
            {
                // Last chance: the legacy "@host" form ('@' at index 0).
                m_kind = NameConstraintHostNameKind.AtHost;
                m_host = value.Substring(1);
            }

            // The host part must be free of empty labels. The Domain form's leading dot is a constraint-only
            // shape (RFC 5280 4.2.1.10), so for a tested name it is validated as part of the host - and
            // rejected as an empty first label.
            int hostStart = m_kind == NameConstraintHostNameKind.Domain
                ? (isConstraint ? 1 : 0)
                : value.Length - m_host.Length;
            NameConstraintUtilities.CheckHostLabels(value, hostStart, "rfc822Name");
        }

        NameConstraintHostNameKind INameConstraintHostName.Kind => m_kind;

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
            case NameConstraintHostNameKind.Mailbox:
                return Platform.EqualsIgnoreCase(email.m_value, constraint.m_value);
            // "@domain" style
            case NameConstraintHostNameKind.AtHost:
                return Platform.EqualsIgnoreCase(email.m_host, constraint.m_host);
            // address in sub domain
            case NameConstraintHostNameKind.Domain:
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
                var email = FromConstraint(NameConstraintUtilities.ExtractIA5String(subtree));

                if (permitted == null)
                {
                    intersect.Add(email);
                }
                else
                {
                    foreach (var _permitted in permitted)
                    {
                        // Existing constraint first: an equal pair keeps the first-registered instance.
                        NameConstraintUtilities.Intersect(_permitted, email, intersect);
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
                // Existing constraint first: an equal pair keeps the first-registered instance.
                NameConstraintUtilities.Union(_excluded, email, union);
            }
            return union;
        }
    }
}
