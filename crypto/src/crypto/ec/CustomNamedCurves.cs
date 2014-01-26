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
                //return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
                BigInteger n = FromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
                BigInteger h = BigInteger.ValueOf(1);
                return new X9ECParameters(curve, G, n, h, S);
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
                //return new X9ECParameters(curve, G, curve.Order, curve.Cofactor, S);
                BigInteger n = FromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
                BigInteger h = BigInteger.ValueOf(1);
                return new X9ECParameters(curve, G, n, h, S);
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
            DefineCurve("secp256k1", SecObjectIdentifiers.SecP256k1, Secp256k1Holder.Instance);
            DefineCurve("secp256r1", SecObjectIdentifiers.SecP256r1, Secp256r1Holder.Instance);

            objIds.Add(Platform.ToLowerInvariant("P-256"), SecObjectIdentifiers.SecP256r1);
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
