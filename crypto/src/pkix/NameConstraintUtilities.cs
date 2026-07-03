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

        internal static string StripTrailingDot(string s)
        {
            // length > 1 so a single bare "." (theoretically the empty-label
            // root) is preserved rather than reduced to "".
            if (s != null && s.Length > 1 && s[s.Length - 1] == '.')
                return s.Substring(0, s.Length - 1);

            return s;
        }

        internal static bool WithinDomain(string testDomain, string domain)
        {
            if (Platform.StartsWith(domain, "."))
            {
                domain = domain.Substring(1);
            }

            // Strip the RFC 1034 root-label trailing dot so the per-label
            // compare doesn't see a phantom empty label.
            testDomain = StripTrailingDot(testDomain);
            domain = StripTrailingDot(domain);

            string[] domainParts = Strings.Split(domain, '.');
            string[] testDomainParts = Strings.Split(testDomain, '.');

            // must have at least one subdomain
            if (testDomainParts.Length <= domainParts.Length)
                return false;

            int d = testDomainParts.Length - domainParts.Length;
            if (testDomainParts[d - 1].Length < 1)
                return false;

            for (int i = 0; i < domainParts.Length; i++)
            {
                if (!Platform.EqualsIgnoreCase(domainParts[i], testDomainParts[d + i]))
                    return false;
            }
            return true;
        }

        // The labels of a domain-constraint value, normalized as WithinDomain normalizes its domain operand:
        // a single leading dot and any trailing dot removed, then split on '.'.
        private static string[] DomainLabels(string domain)
        {
            if (Platform.StartsWith(domain, "."))
            {
                domain = domain.Substring(1);
            }

            return Strings.Split(StripTrailingDot(domain), '.');
        }

        // Classify two domain-constraint values in a single pass - the effort of one WithinDomain, versus the
        // equal-plus-WithinDomain-both-ways it replaces. Each is split into labels once; walking from the
        // least-significant label yields Equal (both exhaust together), Subsumes/SubsumedBy (one is a proper
        // suffix of the other) or Disjoint. The "innermost leftover label must be non-empty" check reproduces
        // WithinDomain's proper-subdomain guard, so results match it (and EqualsIgnoreCase) exactly.
        private static NameConstraintRelation RelateDomains(string domain1, string domain2)
        {
            string[] labels1 = DomainLabels(domain1);
            string[] labels2 = DomainLabels(domain2);

            int i1 = labels1.Length - 1, i2 = labels2.Length - 1;
            while (i1 >= 0 && i2 >= 0)
            {
                if (!Platform.EqualsIgnoreCase(labels1[i1], labels2[i2]))
                    return Disjoint;

                --i1;
                --i2;
            }

            if (i1 < 0 && i2 < 0)
                return Equal;

            // The shorter is a suffix of the longer; the longer is a proper subdomain only if its innermost
            // leftover label is non-empty.
            if (i1 < 0)
                return labels2[i2].Length > 0 ? Subsumes : Disjoint;    // domain1 is shorter -> broader

            return labels1[i1].Length > 0 ? SubsumedBy : Disjoint;      // domain1 is longer -> narrower
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
