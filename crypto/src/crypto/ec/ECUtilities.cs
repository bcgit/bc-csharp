using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;

namespace Org.BouncyCastle.Crypto.EC
{
    internal static class ECUtilities
    {
        internal static X9ECParameters FindECCurveByName(string name) =>
            CustomNamedCurves.GetByName(name) ?? ECNamedCurveTable.GetByName(name);

        internal static X9ECParametersHolder FindECCurveByNameLazy(string name) =>
            CustomNamedCurves.GetByNameLazy(name) ?? ECNamedCurveTable.GetByNameLazy(name);

        internal static X9ECParameters FindECCurveByOid(DerObjectIdentifier oid) =>
            CustomNamedCurves.GetByOid(oid) ?? ECNamedCurveTable.GetByOid(oid);

        internal static X9ECParametersHolder FindECCurveByOidLazy(DerObjectIdentifier oid) =>
            CustomNamedCurves.GetByOidLazy(oid) ?? ECNamedCurveTable.GetByOidLazy(oid);

        internal static DerObjectIdentifier FindECCurveOid(string name) =>
            CustomNamedCurves.GetOid(name) ?? ECNamedCurveTable.GetOid(name);
    }
}
