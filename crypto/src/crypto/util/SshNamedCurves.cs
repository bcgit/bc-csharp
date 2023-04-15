using System.Collections.Generic;
using System.Linq;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;

namespace Org.BouncyCastle.Crypto.Utilities
{
    public class SshNamedCurves
    {
        private static readonly Dictionary<string, DerObjectIdentifier> OidMap =
            new Dictionary<string, DerObjectIdentifier>
            {
                { "nistp256", SecObjectIdentifiers.SecP256r1 },
                { "nistp384", SecObjectIdentifiers.SecP384r1 },
                { "nistp521", SecObjectIdentifiers.SecP521r1 },
                { "nistk163", SecObjectIdentifiers.SecT163k1 },
                { "nistp192", SecObjectIdentifiers.SecP192r1 },
                { "nistp224", SecObjectIdentifiers.SecP224r1 },
                { "nistk233", SecObjectIdentifiers.SecT233k1 },
                { "nistb233", SecObjectIdentifiers.SecT233r1 },
                { "nistk283", SecObjectIdentifiers.SecT283k1 },
                { "nistk409", SecObjectIdentifiers.SecT409k1 },
                { "nistb409", SecObjectIdentifiers.SecT409r1 },
                { "nistt571", SecObjectIdentifiers.SecT571k1 }
            };


        private static readonly Dictionary<string, string> CurveNameToSSHName =
            new Dictionary<string, string>
            {
                {"secp256r1", "nistp256"},
                {"secp384r1", "nistp384"},
                {"secp521r1", "nistp521"},
                {"sect163k1", "nistk163"},
                {"secp192r1", "nistp192"},
                {"secp224r1", "nistp224"},
                {"sect233k1", "nistk233"},
                {"sect233r1", "nistb233"},
                {"sect283k1", "nistk283"},
                {"sect409k1", "nistk409"},
                {"sect409r1", "nistb409"},
                {"sect571k1", "nistt571"}
            };

        private static readonly Dictionary<ECCurve, string> CurveMap =
            CustomNamedCurves.Names.ToDictionary(k => CustomNamedCurves.GetByNameLazy(k).Curve, v => v);

        private static readonly Dictionary<DerObjectIdentifier, string> OidToName =
            OidMap.ToDictionary(k => k.Value, v => v.Key);


        public static DerObjectIdentifier GetByName(string sshName)
        {
            return OidMap[sshName];
        }

        public static X9ECParameters GetParameters(string sshName)
        {
            return NistNamedCurves.GetByOid(OidMap[sshName.ToLower()]);
        }

        public static X9ECParameters GetParameters(DerObjectIdentifier oid)
        {
            return NistNamedCurves.GetByOid(oid);
        }

        public static string GetName(DerObjectIdentifier oid)
        {
            return OidToName[oid];
        }

        public static string GetNameForParameters(ECDomainParameters parameters)
        {
            if (parameters is ECNamedDomainParameters)
            {
                return GetName(((ECNamedDomainParameters)parameters).Name);
            }

            return GetNameForParameters(parameters.Curve);
        }

        public static string GetNameForParameters(ECCurve curve)
        {
            return CurveNameToSSHName[CurveMap[curve]];
        }
    }
}
