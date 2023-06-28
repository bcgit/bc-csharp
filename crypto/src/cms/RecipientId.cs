using System;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    // TODO[api] sealed
    public class RecipientID
        : X509CertStoreSelector, IEquatable<RecipientID>
    {
        private byte[] m_keyIdentifier;

		public byte[] KeyIdentifier
		{
			get { return Arrays.Clone(m_keyIdentifier); }
			set { m_keyIdentifier = Arrays.Clone(value); }
		}

        public virtual bool Equals(RecipientID other)
        {
            return other == null ? false
                :  other == this ? true
                :  Arrays.AreEqual(m_keyIdentifier, other.m_keyIdentifier)
                && MatchesSubjectKeyIdentifier(other)
                && MatchesSerialNumber(other)
                && MatchesIssuer(other);
        }

        public override bool Equals(object obj) => Equals(obj as RecipientID);

        public override int GetHashCode()
        {
            return Arrays.GetHashCode(m_keyIdentifier)
				^  GetHashCodeOfSubjectKeyIdentifier()
                ^  Objects.GetHashCode(SerialNumber)
                ^  Objects.GetHashCode(Issuer);
        }
    }
}
