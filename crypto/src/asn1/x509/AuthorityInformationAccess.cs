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
    public class AuthorityInformationAccess
        : Asn1Encodable
    {
        public static AuthorityInformationAccess GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is AuthorityInformationAccess authorityInformationAccess)
                return authorityInformationAccess;
            return new AuthorityInformationAccess(Asn1Sequence.GetInstance(obj));
        }

        public static AuthorityInformationAccess GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthorityInformationAccess(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static AuthorityInformationAccess GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new AuthorityInformationAccess(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        public static AuthorityInformationAccess FromExtensions(X509Extensions extensions)
        {
            return GetInstance(X509Extensions.GetExtensionParsedValue(extensions, X509Extensions.AuthorityInfoAccess));
        }

        private readonly AccessDescription[] m_descriptions;

        private AuthorityInformationAccess(Asn1Sequence seq)
        {
            if (seq.Count < 1)
                throw new ArgumentException("sequence may not be empty");

            m_descriptions = seq.MapElements(AccessDescription.GetInstance);
        }

        public AuthorityInformationAccess(AccessDescription description)
        {
            m_descriptions = new AccessDescription[]{
                description ?? throw new ArgumentNullException(nameof(description))
            };
        }

        public AuthorityInformationAccess(AccessDescription[] descriptions)
        {
            if (Arrays.IsNullOrContainsNull(descriptions))
                throw new NullReferenceException("'descriptions' cannot be null, or contain null");

            m_descriptions = Copy(descriptions);
        }

        /**
         * create an AuthorityInformationAccess with the oid and location provided.
         */
        public AuthorityInformationAccess(DerObjectIdentifier oid, GeneralName location)
            : this(new AccessDescription(oid, location))
        {
        }

        public AccessDescription[] GetAccessDescriptions() => Copy(m_descriptions);

        public override Asn1Object ToAsn1Object() => new DerSequence(m_descriptions);

        public override string ToString()
        {
            //return "AuthorityInformationAccess: Oid(" + this.descriptions[0].AccessMethod.Id + ")";

            StringBuilder buf = new StringBuilder();
            buf.AppendLine("AuthorityInformationAccess:");
            foreach (AccessDescription description in m_descriptions)
            {
                buf.Append("    ")
                   .Append(description)
                   .AppendLine();
            }
            return buf.ToString();
        }

        private static AccessDescription[] Copy(AccessDescription[] descriptions) =>
            (AccessDescription[])descriptions.Clone();
    }
}
