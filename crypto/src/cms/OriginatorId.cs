using System;

using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509.Store;

namespace Org.BouncyCastle.Cms
{
    // TODO[api] sealed
    public class OriginatorID
        : X509CertStoreSelector, IEquatable<OriginatorID>
    {
        public virtual bool Equals(OriginatorID other)
        {
            return other == null ? false
                :  other == this ? true
                :  MatchesSubjectKeyIdentifier(other)
                && MatchesSerialNumber(other)
                && MatchesIssuer(other);
        }

        public override bool Equals(object obj) => Equals(obj as OriginatorID);

        public override int GetHashCode()
        {
            return GetHashCodeOfSubjectKeyIdentifier()
                ^  Objects.GetHashCode(SerialNumber)
                ^  Objects.GetHashCode(Issuer);
        }
    }
}
