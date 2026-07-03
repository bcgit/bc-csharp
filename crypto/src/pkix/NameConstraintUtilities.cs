using System;
using System.Collections.Generic;
using System.Diagnostics;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities;

using static Org.BouncyCastle.Pkix.NameConstraintRelation;

namespace Org.BouncyCastle.Pkix
{
    /// <summary>Name canonicalisation and matching helpers for name-constraint processing.</summary>
    internal static class NameConstraintUtilities
    {
        internal static string ExtractHostFromURL(string url)
        {
            // RFC 3986 §3.2 authority structure:
            //   authority = [ userinfo "@" ] host [ ":" port ]
            // The strip order is: scheme → "//" → path/query/fragment terminator → userinfo (last '@') → host
            // with optional bracketed IPv6 / trailing ":port".
            string sub = url;
            int schemeEnd = sub.IndexOf(':');
            if (schemeEnd >= 0)
            {
                sub = sub.Substring(schemeEnd + 1);
            }
            if (Platform.StartsWith(sub, "//"))
            {
                sub = sub.Substring(2);
            }
            for (int i = 0; i < sub.Length; ++i)
            {
                char c = sub[i];
                if (c == '/' || c == '?' || c == '#')
                {
                    sub = sub.Substring(0, i);
                    break;
                }
            }
            int atPos = sub.LastIndexOf('@');
            if (atPos >= 0)
            {
                sub = sub.Substring(atPos + 1);
            }
            if (Platform.StartsWith(sub, "["))
            {
                int closeBracket = sub.IndexOf(']');
                if (closeBracket > 0)
                {
                    return sub.Substring(1, closeBracket - 1);
                }
                return sub.Substring(1);
            }
            int portColon = sub.LastIndexOf(':');
            if (portColon >= 0)
            {
                sub = sub.Substring(0, portColon);
            }
            return sub;
        }

        internal static string ExtractIA5String(GeneralSubtree subtree)
        {
            GeneralName baseName = subtree.Base;
            Debug.Assert(baseName.TagNo == GeneralName.Rfc822Name
                || baseName.TagNo == GeneralName.DnsName
                || baseName.TagNo == GeneralName.UniformResourceIdentifier);
            return ExtractIA5String(baseName.Name);
        }

        /// <summary>
        /// Reads a GeneralName value as an IA5String. Only valid for the IA5String-valued GeneralName
        /// choices - rfc822Name, dNSName and uniformResourceIdentifier - so callers must dispatch on the
        /// tag first; any other value throws the same ArgumentException a malformed name would, propagating
        /// per the call site's exception policy.
        /// </summary>
        internal static string ExtractIA5String(Asn1Encodable nameValue) =>
            DerIA5String.GetInstance(nameValue).GetString();

        /// <summary>Is <paramref name="ip"/> a 16-byte IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2)?</summary>
        internal static bool IsIPv4MappedIPv6Address(byte[] ip) =>
            ip != null && ip.Length == 16 && IsIPv4MappedIPv6Address(ip, 0);

        /// <summary>Is the 16-byte span at <paramref name="off"/> an IPv4-mapped IPv6 address (RFC 4291
        /// sec. 2.5.5.2)? The caller must ensure 16 bytes are available from <paramref name="off"/>.</summary>
        internal static bool IsIPv4MappedIPv6Address(byte[] ip, int off)
        {
            for (int i = 0; i < 10; i++)
            {
                if (ip[off + i] != 0)
                    return false;
            }
            return ip[off + 10] == (byte)0xFF && ip[off + 11] == (byte)0xFF;
        }

        // Strip the single RFC 1034 root-label trailing dot, producing the canonical form callers compare on.
        // This is the trailing-dot normalization point for the rfc822Name/URI wrappers (NameConstraintDns
        // validates and strips in its own Create): WithinDomain/DomainLabels rely on canonical input and do
        // not re-strip. Only ONE dot is legitimate - any dot still trailing afterwards is an empty label, left
        // in place for CheckHostLabels to reject. The length > 1 guard preserves a bare "." rather than
        // reducing it to "".
        internal static string StripTrailingDot(string s) =>
            s.Length > 1 && s[s.Length - 1] == '.' ? s.Substring(0, s.Length - 1) : s;

        /// <summary>
        /// Reject an empty label in the host part of a name-constraint value - a '.' at either end of the
        /// tail of <paramref name="s"/> from <paramref name="hostStart"/>, or a ".." within it. Runs after
        /// the single-trailing-dot strip, so a dot still trailing denotes an empty label, not the root. An
        /// empty tail passes: it is not an empty label (such values match by equality alone).
        /// </summary>
        /// <exception cref="PkixNameConstraintValidatorException">for an empty label</exception>
        internal static void CheckHostLabels(string s, int hostStart, string generalNameType)
        {
            int end = s.Length;
            if (hostStart >= end)
                return;

            if (s[hostStart] == '.' || s[end - 1] == '.'
                || s.IndexOf("..", hostStart, StringComparison.Ordinal) >= 0)
            {
                throw new PkixNameConstraintValidatorException(
                    generalNameType + " has an empty label in the host: " + s);
            }
        }

        /// <summary>
        /// Is <paramref name="testDomain"/> a PROPER subdomain of <paramref name="domain"/> - i.e. does it
        /// extend it leftwards by at least one label? The domain may carry the domain-form leading dot
        /// (".example.com" and "example.com" denote the same subtree here); the apex itself never matches.
        /// </summary>
        /// <remarks>
        /// A single case-insensitive suffix comparison, with the '.' label boundary part of the suffix,
        /// replaces the historical per-label walk. The two are exactly equivalent because operands are
        /// label-clean by construction (no empty labels; see the wrapper factories) - a suffix can neither
        /// start mid-label nor hide behind a ".." misalignment.
        /// </remarks>
        internal static bool WithinDomain(string testDomain, string domain)
        {
            int domOff = Platform.StartsWith(domain, ".") ? 1 : 0;
            int domLen = domain.Length - domOff;

            // At least one extra char, then the '.' label boundary, then the domain itself.
            int boundary = testDomain.Length - domLen - 1;
            if (boundary < 1 || testDomain[boundary] != '.')
                return false;

            // Label-clean inputs cannot have an empty innermost extra label (the old per-label walk's
            // guard); assert the invariant rather than re-checking it.
            Debug.Assert(testDomain[boundary - 1] != '.');

            return string.Compare(testDomain, boundary + 1, domain, domOff, domLen,
                StringComparison.OrdinalIgnoreCase) == 0;
        }

        // Classify two domain-constraint values in a single pass - one comparison, versus the
        // equal-plus-WithinDomain-both-ways it condenses. A leading dot excludes the apex (the proper-
        // subtree form); without it the value's own name is in the subtree (the dNSName reading). Equal
        // remainders are Equal only with matching apex treatment - otherwise the apex-inclusive form is the
        // strictly broader set. Unequal-length remainders relate only if the longer is a proper subdomain
        // of the shorter, per WithinDomain's suffix test - then every element of the narrower subtree is a
        // proper subdomain of the broader base either way, so the apex flags cannot matter.
        private static NameConstraintRelation RelateDomains(string domain1, string domain2)
        {
            int off1 = Platform.StartsWith(domain1, ".") ? 1 : 0;
            int off2 = Platform.StartsWith(domain2, ".") ? 1 : 0;
            int len1 = domain1.Length - off1;
            int len2 = domain2.Length - off2;

            if (len1 == len2)
            {
                if (string.Compare(domain1, off1, domain2, off2, len1, StringComparison.OrdinalIgnoreCase) != 0)
                    return Disjoint;

                if (off1 == off2)
                    return Equal;

                return off1 == 0 ? Subsumes : SubsumedBy;   // the apex-inclusive (undotted) form is broader
            }

            if (len1 < len2)
                return WithinDomain(domain2, domain1) ? Subsumes : Disjoint;    // domain1 is broader

            return WithinDomain(domain1, domain2) ? SubsumedBy : Disjoint;      // domain1 is narrower
        }

        // The pairwise subtree set algebra shared by the rfc822Name and uniformResourceIdentifier wrapper
        // types (the URI logic has been a verbatim clone of the rfc822Name logic since long before those
        // types existed). Intersect and Union are thin consumers of the shared Relate classifier; the generic
        // struct constraint keeps the interface dispatch JIT-specialized (no boxing).

        /// <summary>
        /// Classify the set relationship of <paramref name="name1"/> to <paramref name="name2"/>. Two host-name
        /// constraints never partially overlap (a host/mailbox is a point, a domain a subtree), so the result is
        /// always exactly one <see cref="NameConstraintRelation"/>. The per-kind comparisons are the historical
        /// ones verbatim, so Intersect/Union stay behaviour-identical - except that two case-differing-but-equal
        /// values are reported <see cref="NameConstraintRelation.Equal"/> (keeping name1), a ToString-only nuance
        /// since equality and hashing are case-insensitive.
        /// </summary>
        internal static NameConstraintRelation Relate<T>(this T name1, T name2)
            where T : struct, INameConstraintHostName
        {
            // name1 is a particular address
            if (IsParticularAddress(name1.Kind))
            {
                if (IsParticularAddress(name2.Kind))
                    return Platform.EqualsIgnoreCase(name1.Value, name2.Value) ? Equal : Disjoint;

                if (name2.Kind == NameConstraintHostNameKind.Domain)
                    return WithinDomain(name1.Host, name2.Value) ? SubsumedBy : Disjoint;

                // name2 is a particular host
                return Platform.EqualsIgnoreCase(name1.Host, name2.Value) ? SubsumedBy : Disjoint;
            }

            // name1 specifies a domain
            if (name1.Kind == NameConstraintHostNameKind.Domain)
            {
                if (IsParticularAddress(name2.Kind))
                    return WithinDomain(name2.Host, name1.Value) ? Subsumes : Disjoint;

                if (name2.Kind == NameConstraintHostNameKind.Domain)
                    return RelateDomains(name1.Value, name2.Value);

                // name2 is a particular host
                return WithinDomain(name2.Value, name1.Value) ? Subsumes : Disjoint;
            }

            // name1 specifies a host
            if (IsParticularAddress(name2.Kind))
                return Platform.EqualsIgnoreCase(name2.Host, name1.Value) ? Subsumes : Disjoint;

            if (name2.Kind == NameConstraintHostNameKind.Domain)
                return WithinDomain(name1.Value, name2.Value) ? SubsumedBy : Disjoint;

            // name2 is a particular host
            return Platform.EqualsIgnoreCase(name1.Value, name2.Value) ? Equal : Disjoint;
        }

        /// <summary>Add the intersection of <paramref name="name1"/> and <paramref name="name2"/> - the more
        /// restrictive of an overlapping pair, or nothing if disjoint - to <paramref name="intersect"/>.</summary>
        internal static void Intersect<T>(T name1, T name2, HashSet<T> intersect)
            where T : struct, INameConstraintHostName, IEquatable<T>
        {
            switch (name1.Relate(name2))
            {
            case Equal:
            case SubsumedBy:
                intersect.Add(name1);   // name1 is the narrower (or equal)
                break;
            case Subsumes:
                intersect.Add(name2);   // name2 is the narrower
                break;
            case Disjoint:
                break;                  // no intersection
            }
        }

        private static bool IsParticularAddress(NameConstraintHostNameKind kind) =>
            kind == NameConstraintHostNameKind.Mailbox || kind == NameConstraintHostNameKind.AtHost;

        /// <summary>Add the union of <paramref name="name1"/> and <paramref name="name2"/> - the less
        /// restrictive of an overlapping pair, or both if disjoint - to <paramref name="union"/>.</summary>
        internal static void Union<T>(T name1, T name2, HashSet<T> union)
            where T : struct, INameConstraintHostName, IEquatable<T>
        {
            switch (name1.Relate(name2))
            {
            case Equal:
            case Subsumes:
                union.Add(name1);       // name1 is the broader (or equal)
                break;
            case SubsumedBy:
                union.Add(name2);       // name2 is the broader
                break;
            case Disjoint:
                union.Add(name1);
                union.Add(name2);
                break;
            }
        }
    }
}
