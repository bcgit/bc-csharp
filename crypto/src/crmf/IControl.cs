using System;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Crmf;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crmf
{

    public interface IControl
    {
        DerObjectIdentifier Type { get; }

        Asn1Encodable Value { get; }
    }
}
