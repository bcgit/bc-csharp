using System;
using System.Text;

namespace Org.BouncyCastle.Asn1.X509
{
    /**
	* Implementation of the RoleSyntax object as specified by the RFC3281.
	*
	* <pre>
	* RoleSyntax ::= SEQUENCE {
	*                 roleAuthority  [0] GeneralNames OPTIONAL,
	*                 roleName       [1] GeneralName
	*           }
	* </pre>
	*/
    public class RoleSyntax
		: Asn1Encodable
	{
        /**
		 * RoleSyntax factory method.
		 * @param obj the object used to construct an instance of <code>
		 * RoleSyntax</code>. It must be an instance of <code>RoleSyntax
		 * </code> or <code>Asn1Sequence</code>.
		 * @return the instance of <code>RoleSyntax</code> built from the
		 * supplied object.
		 * @throws java.lang.ArgumentException if the object passed
		 * to the factory is not an instance of <code>RoleSyntax</code> or
		 * <code>Asn1Sequence</code>.
		 */
        public static RoleSyntax GetInstance(object obj)
        {
            if (obj == null)
                return null;
            if (obj is RoleSyntax roleSyntax)
                return roleSyntax;
            return new RoleSyntax(Asn1Sequence.GetInstance(obj));
        }

        public static RoleSyntax GetInstance(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RoleSyntax(Asn1Sequence.GetInstance(taggedObject, declaredExplicit));

        public static RoleSyntax GetTagged(Asn1TaggedObject taggedObject, bool declaredExplicit) =>
            new RoleSyntax(Asn1Sequence.GetTagged(taggedObject, declaredExplicit));

        private readonly GeneralNames m_roleAuthority;
        private readonly GeneralName m_roleName;

        /**
		* Constructor that builds an instance of <code>RoleSyntax</code> by
		* extracting the encoded elements from the <code>Asn1Sequence</code>
		* object supplied.
		* @param seq    an instance of <code>Asn1Sequence</code> that holds
		* the encoded elements used to build this <code>RoleSyntax</code>.
		*/
        private RoleSyntax(Asn1Sequence seq)
        {
            int count = seq.Count, pos = 0;
            if (count < 1 || count > 2)
                throw new ArgumentException("Bad sequence size: " + count, nameof(seq));

			m_roleAuthority = Asn1Utilities.ReadOptionalContextTagged(seq, ref pos, 0, false, GeneralNames.GetTagged);
			m_roleName = Asn1Utilities.ReadContextTagged(seq, ref pos, 1, true, GeneralName.GetTagged); // CHOICE

            if (pos != count)
                throw new ArgumentException("Unexpected elements in sequence", nameof(seq));

			// TODO Check role name and URI option as below
        }

        /**
		* Constructor.
		* @param roleAuthority the role authority of this RoleSyntax.
		* @param roleName    the role name of this RoleSyntax.
		*/
        public RoleSyntax(GeneralNames roleAuthority, GeneralName roleName)
        {
            if (roleName == null
				|| roleName.TagNo != GeneralName.UniformResourceIdentifier
				|| ((IAsn1String)roleName.Name).GetString().Equals(""))
			{
				throw new ArgumentException("the role name MUST be non empty and MUST " +
					"use the URI option of GeneralName");
			}

			m_roleAuthority = roleAuthority;
			m_roleName = roleName;
		}

		/**
		* Constructor. Invoking this constructor is the same as invoking
		* <code>new RoleSyntax(null, roleName)</code>.
		* @param roleName    the role name of this RoleSyntax.
		*/
		public RoleSyntax(GeneralName roleName)
			: this(null, roleName)
		{
		}

		/**
		* Utility constructor. Takes a <code>string</code> argument representing
		* the role name, builds a <code>GeneralName</code> to hold the role name
		* and calls the constructor that takes a <code>GeneralName</code>.
		* @param roleName
		*/
		public RoleSyntax(string roleName)
			: this(new GeneralName(GeneralName.UniformResourceIdentifier, roleName == null ? "" : roleName))
		{
		}

		/**
		* Gets the role authority of this RoleSyntax.
		* @return    an instance of <code>GeneralNames</code> holding the
		* role authority of this RoleSyntax.
		*/
		public GeneralNames RoleAuthority => m_roleAuthority;

		/**
		* Gets the role name of this RoleSyntax.
		* @return    an instance of <code>GeneralName</code> holding the
		* role name of this RoleSyntax.
		*/
		public GeneralName RoleName => m_roleName;

		/**
		* Gets the role name as a <code>java.lang.string</code> object.
		* @return    the role name of this RoleSyntax represented as a
		* <code>string</code> object.
		*/
		public string GetRoleNameAsString() => ((IAsn1String)m_roleName.Name).GetString();

		/**
		* Gets the role authority as a <code>string[]</code> object.
		* @return the role authority of this RoleSyntax represented as a
		* <code>string[]</code> array.
		*/
		public string[] GetRoleAuthorityAsString()
		{
            if (m_roleAuthority == null || m_roleAuthority.Count == 0)
                return new string[0];

			GeneralName[] names = m_roleAuthority.GetNames();
			string[] namesString = new string[names.Length];
			for(int i = 0; i < names.Length; i++)
			{
				Asn1Encodable asn1Value = names[i].Name;
				if (asn1Value is IAsn1String asn1String)
				{
					namesString[i] = asn1String.GetString();
				}
				else
				{
					namesString[i] = asn1Value.ToString();
				}
			}
			return namesString;
		}

		/**
		* Implementation of the method <code>ToAsn1Object</code> as
		* required by the superclass <code>ASN1Encodable</code>.
		*
		* <pre>
		* RoleSyntax ::= SEQUENCE {
		*                 roleAuthority  [0] GeneralNames OPTIONAL,
		*                 roleName       [1] GeneralName
		*           }
		* </pre>
		*/
        public override Asn1Object ToAsn1Object()
        {
            Asn1EncodableVector v = new Asn1EncodableVector(2);
            v.AddOptionalTagged(false, 0, m_roleAuthority);
            v.Add(new DerTaggedObject(true, 1, m_roleName));
            return new DerSequence(v);
        }

		public override string ToString()
		{
			StringBuilder buff = new StringBuilder("Name: " + this.GetRoleNameAsString() +
				" - Auth: ");

			if (m_roleAuthority == null || m_roleAuthority.Count == 0)
			{
				buff.Append("N/A");
			}
			else
			{
				string[] names = this.GetRoleAuthorityAsString();
				buff.Append('[').Append(names[0]);
				for(int i = 1; i < names.Length; i++)
				{
					buff.Append(", ").Append(names[i]);
				}
				buff.Append(']');
			}

			return buff.ToString();
		}
	}
}
