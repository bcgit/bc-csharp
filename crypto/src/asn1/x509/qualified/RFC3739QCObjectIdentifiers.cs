using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Asn1.X509.Qualified
{
    // TODO[api] Make static
    public sealed class Rfc3739QCObjectIdentifiers
    {
		private Rfc3739QCObjectIdentifiers()
		{
		}

		//
        // base id
        //
        public static readonly DerObjectIdentifier IdQcs = X509ObjectIdentifiers.IdPkix.Branch("11");

        public static readonly DerObjectIdentifier IdQcsPkixQCSyntaxV1 = IdQcs.Branch("1");
        public static readonly DerObjectIdentifier IdQcsPkixQCSyntaxV2 = IdQcs.Branch("2");
    }
}
