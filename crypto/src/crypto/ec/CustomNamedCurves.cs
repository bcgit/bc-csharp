using System;
using System.Collections;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Custom.Sec;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.EC
{
    public sealed class CustomNamedCurves
    {
        private CustomNamedCurves()
        {
        }

        private static BigInteger FromHex(string hex)
        {
            return new BigInteger(1, Hex.Decode(hex));
        }

        private static ECCurve ConfigureCurve(ECCurve curve)
        {
            return curve;
        }

        /*
         * secp192k1
         */
        internal class Secp192k1Holder
            : X9ECParametersHolder
        {
            private Secp192k1Holder() { }

            internal static readonly X9ECParametersHolder Instance = new Secp192k1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = null;
                ECCurve curve = ConfigureCurve(new SecP192K1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D"
                    + "9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp192r1
         */
        internal class Secp192r1Holder
            : X9ECParametersHolder
        {
            private Secp192r1Holder() { }

            internal static readonly X9ECParametersHolder Instance = new Secp192r1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = Hex.Decode("3045AE6FC8422F64ED579528D38120EAE12196D5");
                ECCurve curve = ConfigureCurve(new SecP192R1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"
                    + "07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp224k1
         */
        internal class Secp224k1Holder
            : X9ECParametersHolder
        {
            private Secp224k1Holder() { }

            internal static readonly X9ECParametersHolder Instance = new Secp224k1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = null;
                ECCurve curve = ConfigureCurve(new SecP224K1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C"
                    + "7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp224r1
         */
        internal class Secp224r1Holder
            : X9ECParametersHolder
        {
            private Secp224r1Holder() { }

            internal static readonly X9ECParametersHolder Instance = new Secp224r1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = Hex.Decode("BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5");
                ECCurve curve = ConfigureCurve(new SecP224R1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"
                    + "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp256k1
         */
        internal class Secp256k1Holder
            : X9ECParametersHolder
        {
            private Secp256k1Holder() {}

            internal static readonly X9ECParametersHolder Instance = new Secp256k1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = null;
                ECCurve curve = ConfigureCurve(new SecP256K1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
                    + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp256r1
         */
        internal class Secp256r1Holder
            : X9ECParametersHolder
        {
            private Secp256r1Holder() {}

            internal static readonly X9ECParametersHolder Instance = new Secp256r1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = Hex.Decode("C49D360886E704936A6678E1139D26B7819F7E90");
                ECCurve curve = ConfigureCurve(new SecP256R1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                    + "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp384r1
         */
        internal class Secp384r1Holder
            : X9ECParametersHolder
        {
            private Secp384r1Holder() { }

            internal static readonly X9ECParametersHolder Instance = new Secp384r1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = Hex.Decode("A335926AA319A27A1D00896A6773A4827ACDAC73");
                ECCurve curve = ConfigureCurve(new SecP384R1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"
                    + "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        /*
         * secp521r1
         */
        internal class Secp521r1Holder
            : X9ECParametersHolder
        {
            private Secp521r1Holder() { }

            internal static readonly X9ECParametersHolder Instance = new Secp521r1Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = Hex.Decode("D09E8800291CB85396CC6717393284AAA0DA64BA");
                ECCurve curve = ConfigureCurve(new SecP521R1Curve());
                ECPoint G = curve.DecodePoint(Hex.Decode("04"
                    + "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"
                    + "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"));
                return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
            }
        }

        private static readonly IDictionary objIds = Platform.CreateHashtable();
        private static readonly IDictionary curves = Platform.CreateHashtable();
        private static readonly IDictionary names = Platform.CreateHashtable();

        private static void DefineCurve(string name, DerObjectIdentifier oid, X9ECParametersHolder holder)
        {
            objIds.Add(name, oid);
            names.Add(oid, name);
            curves.Add(oid, holder);
        }

        static CustomNamedCurves()
        {
            DefineCurve("secp192k1", SecObjectIdentifiers.SecP192k1, Secp192k1Holder.Instance);
            DefineCurve("secp192r1", SecObjectIdentifiers.SecP192r1, Secp192r1Holder.Instance);
            DefineCurve("secp224k1", SecObjectIdentifiers.SecP224k1, Secp224k1Holder.Instance);
            DefineCurve("secp224r1", SecObjectIdentifiers.SecP224r1, Secp224r1Holder.Instance);
            DefineCurve("secp256k1", SecObjectIdentifiers.SecP256k1, Secp256k1Holder.Instance);
            DefineCurve("secp256r1", SecObjectIdentifiers.SecP256r1, Secp256r1Holder.Instance);
            DefineCurve("secp384r1", SecObjectIdentifiers.SecP384r1, Secp384r1Holder.Instance);
            DefineCurve("secp521r1", SecObjectIdentifiers.SecP521r1, Secp521r1Holder.Instance);

            objIds.Add(Platform.ToLowerInvariant("P-192"), SecObjectIdentifiers.SecP192r1);
            objIds.Add(Platform.ToLowerInvariant("P-224"), SecObjectIdentifiers.SecP224r1);
            objIds.Add(Platform.ToLowerInvariant("P-256"), SecObjectIdentifiers.SecP256r1);
            objIds.Add(Platform.ToLowerInvariant("P-384"), SecObjectIdentifiers.SecP384r1);
            objIds.Add(Platform.ToLowerInvariant("P-521"), SecObjectIdentifiers.SecP521r1);
        }

        public static X9ECParameters GetByName(string name)
        {
            DerObjectIdentifier oid = (DerObjectIdentifier)objIds[Platform.ToLowerInvariant(name)];

            return oid == null ? null : GetByOid(oid);
        }

        /**
         * return the X9ECParameters object for the named curve represented by
         * the passed in object identifier. Null if the curve isn't present.
         *
         * @param oid an object identifier representing a named curve, if present.
         */
        public static X9ECParameters GetByOid(DerObjectIdentifier oid)
        {
            X9ECParametersHolder holder = (X9ECParametersHolder)curves[oid];

            return holder == null ? null : holder.Parameters;
        }

        /**
         * return the object identifier signified by the passed in name. Null
         * if there is no object identifier associated with name.
         *
         * @return the object identifier associated with name, if present.
         */
        public static DerObjectIdentifier GetOid(string name)
        {
            return (DerObjectIdentifier)objIds[Platform.ToLowerInvariant(name)];
        }

        /**
         * return the named curve name represented by the given object identifier.
         */
        public static string GetName(DerObjectIdentifier oid)
        {
            return (string)names[oid];
        }

        /**
         * returns an enumeration containing the name strings for curves
         * contained in this structure.
         */
        public static IEnumerable Names
        {
            get { return new EnumerableProxy(objIds.Keys); }
        }
    }
}
