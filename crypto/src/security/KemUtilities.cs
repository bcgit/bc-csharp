using System;
using System.Collections.Generic;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Security
{
    public static class KemUtilities
    {
        private static readonly Dictionary<string, string> ByName =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> ByOid =
            new Dictionary<DerObjectIdentifier, string>();

        static KemUtilities()
        {
            /*
             * ML-KEM
             */
            foreach (MLKemParameters mlKem in MLKemParameters.ByName.Values)
            {
                Register(mlKem.Name, mlKem.Oid);
            }

#if DEBUG
            foreach (var name in ByName.Keys)
            {
                // OIDS have their own lookup
                if (DerObjectIdentifier.TryFromID(name, out var ignore))
                    throw new Exception($"OID mapping belongs in {nameof(ByOid)}: {name}");
            }

            var mechanisms = new HashSet<string>(ByName.Values);
            mechanisms.UnionWith(ByOid.Values);

            foreach (var mechanism in mechanisms)
            {
                // All mechanisms must have a self-mapping
                if (!ByName.TryGetValue(mechanism, out var check) || check != mechanism)
                    throw new Exception($"Mechanism must have {nameof(ByName)} mapping to self: {mechanism}");
            }
#endif
        }

        private static void Register(string name, DerObjectIdentifier oid)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            ByName.Add(name, name);

            if (oid != null)
            {
                ByOid.Add(oid, name);
            }
        }

        internal static byte[] Decapsulate(IKemDecapsulator kemDecapsulator, byte[] encBuf, int encOff, int encLen)
        {
            if (kemDecapsulator == null)
                throw new ArgumentNullException(nameof(kemDecapsulator));

            byte[] sec = new byte[kemDecapsulator.SecretLength];
            kemDecapsulator.Decapsulate(encBuf, encOff, encLen, sec, 0, sec.Length);
            return sec;
        }

        internal static Tuple<byte[], byte[]> Encapsulate(IKemEncapsulator kemEncapsulator)
        {
            if (kemEncapsulator == null)
                throw new ArgumentNullException(nameof(kemEncapsulator));

            byte[] enc = new byte[kemEncapsulator.EncapsulationLength];
            byte[] sec = new byte[kemEncapsulator.SecretLength];
            kemEncapsulator.Encapsulate(enc, 0, enc.Length, sec, 0, sec.Length);
            return Tuple.Create(enc, sec);
        }

        public static IKemDecapsulator GetDecapsulator(DerObjectIdentifier oid)
        {
            if (TryGetDecapsulator(oid, out var decapsulator))
                return decapsulator;

            throw new SecurityUtilityException("KEM OID not recognised.");
        }

        public static IKemDecapsulator GetDecapsulator(string name)
        {
            if (TryGetDecapsulator(name, out var decapsulator))
                return decapsulator;

            throw new SecurityUtilityException("KEM name not recognised.");
        }

        public static IKemEncapsulator GetEncapsulator(DerObjectIdentifier oid)
        {
            if (TryGetEncapsulator(oid, out var encapsulator))
                return encapsulator;

            throw new SecurityUtilityException("KEM OID not recognised.");
        }

        public static IKemEncapsulator GetEncapsulator(string name)
        {
            if (TryGetEncapsulator(name, out var encapsulator))
                return encapsulator;

            throw new SecurityUtilityException("KEM name not recognised.");
        }

        public static bool TryGetDecapsulator(DerObjectIdentifier oid, out IKemDecapsulator decapsulator)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (TryGetMechanism(oid, out var mechanism))
            {
                var decap = GetDecapForMechanism(mechanism);
                if (decap != null)
                {
                    decapsulator = decap;
                    return true;
                }
            }

            decapsulator = default;
            return false;
        }

        public static bool TryGetDecapsulator(string name, out IKemDecapsulator decapsulator)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            if (TryGetMechanism(name, out var mechanism))
            {
                var decap = GetDecapForMechanism(mechanism);
                if (decap != null)
                {
                    decapsulator = decap;
                    return true;
                }
            }

            decapsulator = default;
            return false;
        }

        public static bool TryGetEncapsulator(DerObjectIdentifier oid, out IKemEncapsulator encapsulator)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (TryGetMechanism(oid, out var mechanism))
            {
                var encap = GetEncapForMechanism(mechanism);
                if (encap != null)
                {
                    encapsulator = encap;
                    return true;
                }
            }

            encapsulator = default;
            return false;
        }

        public static bool TryGetEncapsulator(string name, out IKemEncapsulator encapsulator)
        {
            if (name == null)
                throw new ArgumentNullException(nameof(name));

            if (TryGetMechanism(name, out var mechanism))
            {
                var encap = GetEncapForMechanism(mechanism);
                if (encap != null)
                {
                    encapsulator = encap;
                    return true;
                }
            }

            encapsulator = default;
            return false;
        }

        private static IKemDecapsulator GetDecapForMechanism(string mechanism)
        {
            if (MLKemParameters.ByName.TryGetValue(mechanism, out MLKemParameters mlKemParameters))
                return new MLKemDecapsulator(mlKemParameters);

            return null;
        }

        private static IKemEncapsulator GetEncapForMechanism(string mechanism)
        {
            if (MLKemParameters.ByName.TryGetValue(mechanism, out MLKemParameters mlKemParameters))
                return new MLKemEncapsulator(mlKemParameters);

            return null;
        }

        private static bool TryGetMechanism(DerObjectIdentifier oid, out string mechanism) =>
            ByOid.TryGetValue(oid, out mechanism);

        private static bool TryGetMechanism(string name, out string mechanism)
        {
            if (DerObjectIdentifier.TryFromID(name, out var oid))
                return TryGetMechanism(oid, out mechanism);

            return ByName.TryGetValue(name, out mechanism);
        }
    }
}
