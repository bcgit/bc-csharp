using System;
using System.Text;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
     * The AuthorityInformationAccess object.
     * <pre>
     * id-pe-authorityInfoAccess OBJECT IDENTIFIER ::= { id-pe 1 }
     *
     * AuthorityInfoAccessSyntax  ::=
     *      Sequence SIZE (1..MAX) OF AccessDescription
     * AccessDescription  ::=  Sequence {
     *       accessMethod          OBJECT IDENTIFIER,
     *       accessLocation        GeneralName  }
     *
     * id-ad OBJECT IDENTIFIER ::= { id-pkix 48 }
     * id-ad-caIssuers OBJECT IDENTIFIER ::= { id-ad 2 }
     * id-ad-ocsp OBJECT IDENTIFIER ::= { id-ad 1 }
     * </pre>
     */
    // TODO[api] Name should really be 'AuthorityInfoAccessSyntax'
    public class AuthorityInformationAccess
        : Asn1Encodable
    {
        /// <summary>Return an <see cref="AuthorityInformationAccess"/> from the given object.</summary>
        /// <param name="obj">
        /// An <see cref="AuthorityInformationAccess"/>, an object from which one can be constructed, or null.
        /// </param>
        /// <returns>The <see cref="AuthorityInformationAccess"/>, or null if <paramref name="obj"/> is null.</returns>
        public static AuthorityInformationAccess GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthorityInformationAccess authorityInformationAccess)
                return authorityInformationAccess;
            return new AuthorityInformationAccess(Asn1Sequence.GetInstance(obj));
        }

        /// <summary>Return an <see cref="AuthorityInformationAccess"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AuthorityInformationAccess"/>.</returns>
        public static AuthorityInformationAccess GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthorityInformationAccess(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        /// <summary>Return an <see cref="AuthorityInformationAccess"/> from the given element, if it is one.</summary>
        /// <param name="element">The element.</param>
        /// <returns>
        /// The <see cref="AuthorityInformationAccess"/>, or null if <paramref name="element"/> is null.
        /// </returns>
        public static AuthorityInformationAccess GetOptional(Asn1Encodable element)
        {
            if (element == null)
                throw new ArgumentNullException(nameof(element));

            if (element is AuthorityInformationAccess authorityInformationAccess)
                return authorityInformationAccess;

            Asn1Sequence asn1Sequence = Asn1Sequence.GetOptional(element);
            if (asn1Sequence != null)
                return new AuthorityInformationAccess(asn1Sequence);

            return null;
        }

        /// <summary>Return an <see cref="AuthorityInformationAccess"/> from a tagged object.</summary>
        /// <param name="taggedObject">The tagged object.</param>
        /// <param name="declaredExplicit">true if the tagging is explicit, false if implicit.</param>
        /// <returns>The <see cref="AuthorityInformationAccess"/>.</returns>
        public static AuthorityInformationAccess GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthorityInformationAccess(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        /// <summary>Get the extension of this type from a table of extensions, if it is present.</summary>
        /// <param name="extensions">The extensions, or null.</param>
        /// <returns>The value, or null if the extension is not present.</returns>
        public static AuthorityInformationAccess FromExtensions(X509Extensions extensions) =>
            GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.AuthorityInfoAccess));

        // TODO[asn1] Tighten to DLSequence if/when safe
        private readonly DerSequence m_elements;

        private AuthorityInformationAccess(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(seq));

            m_elements = DerSequence.Map(seq, AccessDescription.GetInstance);
        }

        /// <summary>Create a new <see cref="AuthorityInformationAccess"/>.</summary>
        /// <param name="description">The description.</param>
        public AuthorityInformationAccess(AccessDescription description)
        {
            m_elements = DerSequence.FromElement(description ?? throw new ArgumentNullException(nameof(description)));
        }

        /// <summary>Create a new <see cref="AuthorityInformationAccess"/>.</summary>
        /// <param name="descriptions">The descriptions.</param>
        public AuthorityInformationAccess(AccessDescription[] descriptions)
        {
            if (Arrays.IsNullOrContainsNull(descriptions))
                throw new ArgumentNullException(nameof(descriptions), "cannot be null, or contain null");
            if (descriptions.Length < 1)
                throw new ArgumentException("Minimum sequence size is 1", nameof(descriptions));

            m_elements = DerSequence.FromElements(descriptions);
        }

        /// <summary>Create an AuthorityInformationAccess with the oid and location provided.</summary>
        public AuthorityInformationAccess(DerObjectIdentifier oid, GeneralName location)
            : this(new AccessDescription(oid, location))
        {
        }

        /// <summary>Return the access descriptions.</summary>
        public AccessDescription[] GetAccessDescriptions() => m_elements.MapElements(AccessDescription.GetInstance);

        /// <inheritdoc/>
        public override Asn1Object ToAsn1Object() => m_elements;

        /// <inheritdoc/>
        public override string ToString()
        {
            StringBuilder buf = new StringBuilder();
            buf.AppendLine("AuthorityInformationAccess:");
            // Elements are known to be AccessDescription by construction
            foreach (AccessDescription description in m_elements)
            {
                buf.Append("    ")
                   .Append(description)
                   .AppendLine();
            }
            return buf.ToString();
        }
    }
}
