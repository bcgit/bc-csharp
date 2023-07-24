using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Pkcs
{
    public class Pkcs12Store
    {
        public const string IgnoreUselessPasswordProperty = "Org.BouncyCastle.Pkcs12.IgnoreUselessPassword";

        private readonly Dictionary<string, AsymmetricKeyEntry> m_keys =
            new Dictionary<string, AsymmetricKeyEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, string> m_localIds = new Dictionary<string, string>();
        private readonly Dictionary<string, X509CertificateEntry> m_certs =
            new Dictionary<string, X509CertificateEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<CertID, X509CertificateEntry> m_chainCerts =
            new Dictionary<CertID, X509CertificateEntry>();
        private readonly Dictionary<string, X509CertificateEntry> m_keyCerts =
            new Dictionary<string, X509CertificateEntry>();
        private readonly List<string> m_keysOrder =
            new List<string>();
        private readonly List<string> m_certsOrder =
            new List<string>();
        private readonly List<CertID> m_chainCertOrder =
            new List<CertID>();
        private readonly DerObjectIdentifier keyAlgorithm;
        private readonly DerObjectIdentifier keyPrfAlgorithm;
        private readonly DerObjectIdentifier certAlgorithm;
        private readonly bool useDerEncoding;
        private readonly bool isReverse;

        private AsymmetricKeyEntry unmarkedKeyEntry = null;

        private const int MinIterations = 1024;
        private const int SaltSize = 20;

        private static SubjectKeyIdentifier CreateSubjectKeyID(AsymmetricKeyParameter pubKey)
        {
            return new SubjectKeyIdentifier(
                SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey));
        }

        internal struct CertID
            : IEquatable<CertID>
        {
            private readonly byte[] m_id;

            internal CertID(X509CertificateEntry certEntry)
                : this(certEntry.Certificate)
            {
            }

            internal CertID(X509Certificate cert)
                : this(CreateSubjectKeyID(cert.GetPublicKey()).GetKeyIdentifier())
            {
            }

            internal CertID(byte[] id)
            {
                m_id = id;
            }

            internal byte[] ID => m_id;

            public bool Equals(CertID other) => Arrays.AreEqual(m_id, other.m_id);

            public override bool Equals(object obj) => obj is CertID other && Equals(other);

            public override int GetHashCode() => Arrays.GetHashCode(m_id);
        }

        internal Pkcs12Store(DerObjectIdentifier keyAlgorithm, DerObjectIdentifier keyPrfAlgorithm,
            DerObjectIdentifier certAlgorithm, bool useDerEncoding, bool isReverse)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.keyPrfAlgorithm = keyPrfAlgorithm;
            this.certAlgorithm = certAlgorithm;
            this.useDerEncoding = useDerEncoding;
            this.isReverse = isReverse;
        }

        protected virtual void LoadKeyBag(PrivateKeyInfo privKeyInfo, Asn1Set bagAttributes)
        {
            AsymmetricKeyParameter privKey = PrivateKeyFactory.CreateKey(privKeyInfo);

            var attributes = new Dictionary<DerObjectIdentifier, Asn1Encodable>();
            AsymmetricKeyEntry keyEntry = new AsymmetricKeyEntry(privKey, attributes);

            string alias = null;
            Asn1OctetString localId = null;

            if (bagAttributes != null)
            {
                foreach (Asn1Sequence sq in bagAttributes)
                {
                    DerObjectIdentifier aOid = DerObjectIdentifier.GetInstance(sq[0]);
                    Asn1Set attrSet = Asn1Set.GetInstance(sq[1]);
                    Asn1Encodable attr = null;

                    if (attrSet.Count > 0)
                    {
                        // TODO We should be adding all attributes in the set
                        attr = attrSet[0];

                        // TODO We might want to "merge" attribute sets with
                        // the same OID - currently, differing values give an error
                        if (attributes.TryGetValue(aOid, out var attributeValue))
                        {
                            // OK, but the value has to be the same
                            if (!attributeValue.Equals(attr))
                                throw new IOException("attempt to add existing attribute with different value");
                        }
                        else
                        {
                            attributes[aOid] = attr;
                        }

                        if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtFriendlyName))
                        {
                            alias = ((DerBmpString)attr).GetString();
                            // TODO Do these in a separate loop, just collect aliases here
                            m_keys[alias] = keyEntry;
                            m_keysOrder.Add(alias);
                        }
                        else if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID))
                        {
                            localId = (Asn1OctetString)attr;
                        }
                    }
                }
            }

            if (localId != null)
            {
                string name = Hex.ToHexString(localId.GetOctets());

                if (alias == null)
                {
                    m_keys[name] = keyEntry;
                    m_keysOrder.Add(name);
                }
                else
                {
                    // TODO There may have been more than one alias
                    m_localIds[alias] = name;
                }
            }
            else
            {
                unmarkedKeyEntry = keyEntry;
            }
        }

        protected virtual void LoadPkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo encPrivKeyInfo, Asn1Set bagAttributes,
            char[] password, bool wrongPkcs12Zero)
        {
            if (password != null)
            {
                PrivateKeyInfo privInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(
                    password, wrongPkcs12Zero, encPrivKeyInfo);

                LoadKeyBag(privInfo, bagAttributes);
            }
        }

        public void Load(Stream input, char[] password)
        {
            if (input == null)
                throw new ArgumentNullException("input");

            Pfx bag = Pfx.GetInstance(Asn1Object.FromStream(input));
            ContentInfo info = bag.AuthSafe;
            bool wrongPkcs12Zero = false;

            if (bag.MacData != null) // check the mac code
            {
                if (password == null)
                    throw new ArgumentNullException("password", "no password supplied when one expected");

                MacData mData = bag.MacData;
                DigestInfo dInfo = mData.Mac;
                AlgorithmIdentifier algId = dInfo.AlgorithmID;
                byte[] salt = mData.GetSalt();
                int itCount = mData.IterationCount.IntValue;

                byte[] data = Asn1OctetString.GetInstance(info.Content).GetOctets();

                byte[] mac = CalculatePbeMac(algId.Algorithm, salt, itCount, password, false, data);
                byte[] dig = dInfo.GetDigest();

                if (!Arrays.FixedTimeEquals(mac, dig))
                {
                    if (password.Length > 0)
                        throw new IOException("PKCS12 key store MAC invalid - wrong password or corrupted file.");

                    // Try with incorrect zero length password
                    mac = CalculatePbeMac(algId.Algorithm, salt, itCount, password, true, data);

                    if (!Arrays.FixedTimeEquals(mac, dig))
                        throw new IOException("PKCS12 key store MAC invalid - wrong password or corrupted file.");

                    wrongPkcs12Zero = true;
                }
            }
            else if (password != null)
            {
                string ignoreProperty = Platform.GetEnvironmentVariable(IgnoreUselessPasswordProperty);
                bool ignore = ignoreProperty != null && Platform.EqualsIgnoreCase("true", ignoreProperty);

                if (!ignore)
                {
                    throw new IOException("password supplied for keystore that does not require one");
                }
            }

            m_keys.Clear();
            m_keysOrder.Clear();
            m_localIds.Clear();
            unmarkedKeyEntry = null;

            var certBags = new List<SafeBag>();

            if (info.ContentType.Equals(PkcsObjectIdentifiers.Data))
            {
                Asn1OctetString content = Asn1OctetString.GetInstance(info.Content);
                AuthenticatedSafe authSafe = AuthenticatedSafe.GetInstance(content.GetOctets());
                ContentInfo[] cis = authSafe.GetContentInfo();

                foreach (ContentInfo ci in cis)
                {
                    DerObjectIdentifier oid = ci.ContentType;

                    byte[] octets = null;
                    if (oid.Equals(PkcsObjectIdentifiers.Data))
                    {
                        octets = Asn1OctetString.GetInstance(ci.Content).GetOctets();
                    }
                    else if (oid.Equals(PkcsObjectIdentifiers.EncryptedData))
                    {
                        if (password != null)
                        {
                            EncryptedData d = EncryptedData.GetInstance(ci.Content);
                            octets = CryptPbeData(false, d.EncryptionAlgorithm,
                                password, wrongPkcs12Zero, d.Content.GetOctets());
                        }
                    }
                    else
                    {
                        // TODO Other data types
                    }

                    if (octets != null)
                    {
                        Asn1Sequence seq = Asn1Sequence.GetInstance(octets);

                        foreach (Asn1Sequence subSeq in seq)
                        {
                            SafeBag b = SafeBag.GetInstance(subSeq);

                            if (b.BagID.Equals(PkcsObjectIdentifiers.CertBag))
                            {
                                certBags.Add(b);
                            }
                            else if (b.BagID.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
                            {
                                LoadPkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo.GetInstance(b.BagValue),
                                    b.BagAttributes, password, wrongPkcs12Zero);
                            }
                            else if (b.BagID.Equals(PkcsObjectIdentifiers.KeyBag))
                            {
                                LoadKeyBag(PrivateKeyInfo.GetInstance(b.BagValue), b.BagAttributes);
                            }
                            else
                            {
                                // TODO Other bag types
                            }
                        }
                    }
                }
            }

            m_certs.Clear();
            m_chainCerts.Clear();
            m_keyCerts.Clear();
            m_certsOrder.Clear();
            m_chainCertOrder.Clear();
            
            foreach (SafeBag b in certBags)
            {
                CertBag certBag = CertBag.GetInstance(b.BagValue);
                byte[] octets = ((Asn1OctetString)certBag.CertValue).GetOctets();
                X509Certificate cert = new X509CertificateParser().ReadCertificate(octets);

                //
                // set the attributes
                //
                var attributes = new Dictionary<DerObjectIdentifier, Asn1Encodable>();
                Asn1OctetString localId = null;
                string alias = null;

                if (b.BagAttributes != null)
                {
                    foreach (Asn1Sequence sq in b.BagAttributes)
                    {
                        DerObjectIdentifier aOid = DerObjectIdentifier.GetInstance(sq[0]);
                        Asn1Set attrSet = Asn1Set.GetInstance(sq[1]);

                        if (attrSet.Count > 0)
                        {
                            // TODO We should be adding all attributes in the set
                            Asn1Encodable attr = attrSet[0];

                            // TODO We might want to "merge" attribute sets with
                            // the same OID - currently, differing values give an error
                            if (attributes.TryGetValue(aOid, out var attributeValue))
                            {
                                // we've found more than one - one might be incorrect
                                if (PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(aOid))
                                {
                                    string id = Hex.ToHexString(Asn1OctetString.GetInstance(attr).GetOctets());
                                    if (!m_keys.ContainsKey(id) && !m_localIds.ContainsKey(id))
                                        continue; // ignore this one - it's not valid
                                }

                                // OK, but the value has to be the same
                                if (!attributeValue.Equals(attr))
                                {
                                    throw new IOException("attempt to add existing attribute with different value");
                                }
                            }
                            else
                            {
                                attributes[aOid] = attr;
                            }

                            if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtFriendlyName))
                            {
                                alias = ((DerBmpString)attr).GetString();
                            }
                            else if (aOid.Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID))
                            {
                                localId = (Asn1OctetString)attr;
                            }
                        }
                    }
                }

                CertID certID = new CertID(cert);
                X509CertificateEntry certEntry = new X509CertificateEntry(cert, attributes);

                m_chainCerts[certID] = certEntry;
                m_chainCertOrder.Add(certID);
                // m_certOrder.Add(certID);

                if (unmarkedKeyEntry != null)
                {
                    if (m_keyCerts.Count == 0)
                    {
                        string name = Hex.ToHexString(certID.ID);

                        m_keyCerts[name] = certEntry;
                        m_keys[name] = unmarkedKeyEntry;
                    }
                    else
                    {
                        m_keys["unmarked"] = unmarkedKeyEntry;
                    }
                }
                else
                {
                    if (localId != null)
                    {
                        string name = Hex.ToHexString(localId.GetOctets());

                        m_keyCerts[name] = certEntry;
                    }

                    if (alias != null)
                    {
                        // TODO There may have been more than one alias
                        m_certs[alias] = certEntry;
                        m_certsOrder.Add(alias);
                    }
                }
            }
        }

        public AsymmetricKeyEntry GetKey(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            return CollectionUtilities.GetValueOrNull(m_keys, alias);
        }

        public bool IsCertificateEntry(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            return m_certs.ContainsKey(alias) && !m_keys.ContainsKey(alias);
        }

        public bool IsKeyEntry(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            return m_keys.ContainsKey(alias);
        }

        public IEnumerable<string> Aliases
        {
            get
            {
                var aliases = new HashSet<string>(m_certs.Keys);
                aliases.UnionWith(m_keys.Keys);
                return CollectionUtilities.Proxy(aliases);
            }
        }

        public bool ContainsAlias(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            return m_certs.ContainsKey(alias) || m_keys.ContainsKey(alias);
        }

        /**
         * simply return the cert entry for the private key
         */
        public X509CertificateEntry GetCertificate(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            if (m_certs.TryGetValue(alias, out var cert))
                return cert;

            var keyCertKey = alias;
            if (m_localIds.TryGetValue(alias, out var localId))
            {
                keyCertKey = localId;
            }

            return CollectionUtilities.GetValueOrNull(m_keyCerts, keyCertKey);
        }

        public string GetCertificateAlias(X509Certificate cert)
        {
            if (cert == null)
                throw new ArgumentNullException(nameof(cert));

            foreach (var entry in m_certs)
            {
                if (entry.Value.Certificate.Equals(cert))
                    return entry.Key;
            }

            foreach (var entry in m_keyCerts)
            {
                if (entry.Value.Certificate.Equals(cert))
                    return entry.Key;
            }

            return null;
        }

        public X509CertificateEntry[] GetCertificateChain(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            if (!IsKeyEntry(alias))
                return null;

            X509CertificateEntry c = GetCertificate(alias);
            if (c == null)
                return null;

            var cs = new List<X509CertificateEntry>();

            while (c != null)
            {
                X509Certificate x509c = c.Certificate;
                X509CertificateEntry nextC = null;

                Asn1OctetString akiValue = x509c.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
                if (akiValue != null)
                {
                    AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.GetInstance(akiValue.GetOctets());

                    byte[] keyID = aki.GetKeyIdentifier();
                    if (keyID != null)
                    {
                        nextC = CollectionUtilities.GetValueOrNull(m_chainCerts, new CertID(keyID));
                    }
                }

                if (nextC == null)
                {
                    //
                    // no authority key id, try the Issuer DN
                    //
                    X509Name i = x509c.IssuerDN;
                    X509Name s = x509c.SubjectDN;

                    if (!i.Equivalent(s))
                    {
                        foreach (var entry in m_chainCerts)
                        {
                            X509Certificate cert = entry.Value.Certificate;

                            if (cert.SubjectDN.Equivalent(i))
                            {
                                try
                                {
                                    x509c.Verify(cert.GetPublicKey());

                                    nextC = entry.Value;
                                    break;
                                }
                                catch (InvalidKeyException)
                                {
                                    // TODO What if it doesn't verify?
                                }
                            }
                        }
                    }
                }

                cs.Add(c);
                if (nextC != c) // self signed - end of the chain
                {
                    c = nextC;
                }
                else
                {
                    c = null;
                }
            }

            return cs.ToArray();
        }

        public void SetCertificateEntry(string alias, X509CertificateEntry certEntry)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));
            if (certEntry == null)
                throw new ArgumentNullException(nameof(certEntry));
            if (m_keys.ContainsKey(alias))
                throw new ArgumentException("There is a key entry with the name " + alias + ".");

            m_certs[alias] = certEntry;
            m_chainCerts[new CertID(certEntry)] = certEntry;
        }

        public void SetKeyEntry(string alias, AsymmetricKeyEntry keyEntry, X509CertificateEntry[] chain)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));
            if (keyEntry == null)
                throw new ArgumentNullException(nameof(keyEntry));
            if (keyEntry.Key.IsPrivate && Arrays.IsNullOrEmpty(chain))
                throw new ArgumentException("No certificate chain for private key");

            if (m_keys.ContainsKey(alias))
            {
                DeleteEntry(alias);
            }

            m_keys[alias] = keyEntry;
            m_keysOrder.Add(alias);

            if (chain.Length > 0)
            {
                m_certs[alias] = chain[0];
                m_certsOrder.Add(alias);
                foreach (var certificateEntry in chain)
                {
                    CertID certId = new CertID(certificateEntry);
                    m_chainCerts[certId] = certificateEntry;
                    m_chainCertOrder.Add(certId);
                }
            }
        }

        public void DeleteEntry(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            if (CollectionUtilities.Remove(m_certs, alias, out var certEntry))
            {
                CertID certId = new CertID(certEntry);
                m_chainCerts.Remove(certId);
                m_chainCertOrder.Remove(certId);
                m_certsOrder.Remove(alias);
            }

            if (m_keys.Remove(alias))
            {
                m_keys.Remove(alias);
                if (CollectionUtilities.Remove(m_localIds, alias, out var id))
                {
                    if (CollectionUtilities.Remove(m_keyCerts, id, out var keyCertEntry))
                    {
                        CertID certId = new CertID(certEntry);
                        m_chainCertOrder.Remove(certId);
                        m_chainCerts.Remove(certId);
                    }
                }
            }
        }

        public bool IsEntryOfType(string alias, Type entryType)
        {
            if (entryType == typeof(X509CertificateEntry))
                return IsCertificateEntry(alias);

            if (entryType == typeof(AsymmetricKeyEntry))
                return IsKeyEntry(alias) && GetCertificate(alias) != null;

            return false;
        }

        public int Count
        {
            get
            {
                int count = m_certs.Count;

                foreach (var key in m_keys.Keys)
                {
                    if (!m_certs.ContainsKey(key))
                    {
                        ++count;
                    }
                }

                return count;
            }
        }

        public void Save(Stream stream, char[] password, SecureRandom random)
        {
            if (stream == null)
                throw new ArgumentNullException(nameof(stream));
            if (random == null)
                throw new ArgumentNullException(nameof(random));

            //
            // handle the keys
            //
            Asn1EncodableVector keyBags = new Asn1EncodableVector(m_keys.Count);
            for (uint i = isReverse ? (uint)m_keysOrder.Count-1 : 0;
                 i < m_keysOrder.Count;
                 i = isReverse ? i-1 : i+1)
            {
                var name = m_keysOrder[(int)i];
                var privKey = m_keys[name];

                byte[] kSalt = new byte[SaltSize];
                random.NextBytes(kSalt);

                DerObjectIdentifier bagOid;
                Asn1Encodable bagData;

                if (password == null)
                {
                    bagOid = PkcsObjectIdentifiers.KeyBag;
                    bagData = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privKey.Key);
                }
                else
                {
                    bagOid = PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag;
                    if (keyPrfAlgorithm != null)
                    {
                        bagData = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(keyAlgorithm,
                            keyPrfAlgorithm, password, kSalt, MinIterations, random, privKey.Key);
                    }
                    else
                    {
                        bagData = EncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(keyAlgorithm, password,
                            kSalt, MinIterations, privKey.Key);
                    }
                }

                Asn1EncodableVector kName = new Asn1EncodableVector();

                foreach (var oid in privKey.BagAttributeKeys)
                {
                    // NB: Ignore any existing FriendlyName
                    if (!PkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(oid))
                    {
                        kName.Add(new DerSequence(oid, new DerSet(privKey[oid])));
                    }
                }

                //
                // make sure we are using the local alias on store
                //
                // NB: We always set the FriendlyName based on 'name'
                //if (privKey[PkcsObjectIdentifiers.Pkcs9AtFriendlyName] == null)
                {
                    kName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                            new DerSet(new DerBmpString(name))));
                }

                //
                // make sure we have a local key-id
                //
                if (privKey[PkcsObjectIdentifiers.Pkcs9AtLocalKeyID] == null)
                {
                    X509CertificateEntry ct = GetCertificate(name);
                    AsymmetricKeyParameter pubKey = ct.Certificate.GetPublicKey();
                    SubjectKeyIdentifier subjectKeyID = CreateSubjectKeyID(pubKey);

                    kName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtLocalKeyID,
                            new DerSet(subjectKeyID)));
                }

                keyBags.Add(new SafeBag(bagOid, bagData.ToAsn1Object(), DerSet.FromVector(kName)));
            }

            byte[] keyBagsEncoding = new DerSequence(keyBags).GetDerEncoded();
            ContentInfo keysInfo = new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(keyBagsEncoding));

            //
            // certificate processing
            //
            byte[] cSalt = new byte[SaltSize];

            random.NextBytes(cSalt);

            Asn1EncodableVector certBags = new Asn1EncodableVector(m_keys.Count);
            Pkcs12PbeParams     cParams = new Pkcs12PbeParams(cSalt, MinIterations);
            AlgorithmIdentifier cAlgId = new AlgorithmIdentifier(certAlgorithm, cParams.ToAsn1Object());
            var doneCerts = new HashSet<X509Certificate>();

            for (uint i = isReverse ? (uint)m_keysOrder.Count-1 : 0;
                 i < m_keysOrder.Count;
                 i = isReverse ? i-1 : i+1)
            {
                String name = m_keysOrder[(int)i];
                X509CertificateEntry certEntry = GetCertificate(name);
                CertBag cBag = new CertBag(
                    PkcsObjectIdentifiers.X509Certificate,
                    new DerOctetString(certEntry.Certificate.GetEncoded()));

                Asn1EncodableVector fName = new Asn1EncodableVector();

                foreach (var oid in certEntry.BagAttributeKeys)
                {
                    // NB: Ignore any existing FriendlyName
                    if (!PkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(oid))
                    {
                        fName.Add(new DerSequence(oid, new DerSet(certEntry[oid])));
                    }
                }

                //
                // make sure we are using the local alias on store
                //
                // NB: We always set the FriendlyName based on 'name'
                //if (certEntry[PkcsObjectIdentifiers.Pkcs9AtFriendlyName] == null)
                {
                    fName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                            new DerSet(new DerBmpString(name))));
                }

                //
                // make sure we have a local key-id
                //
                if (certEntry[PkcsObjectIdentifiers.Pkcs9AtLocalKeyID] == null)
                {
                    AsymmetricKeyParameter pubKey = certEntry.Certificate.GetPublicKey();
                    SubjectKeyIdentifier subjectKeyID = CreateSubjectKeyID(pubKey);

                    fName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtLocalKeyID,
                            new DerSet(subjectKeyID)));
                }

                certBags.Add(new SafeBag(PkcsObjectIdentifiers.CertBag, cBag.ToAsn1Object(), DerSet.FromVector(fName)));

                doneCerts.Add(certEntry.Certificate);
            }
            
            // foreach (var certEntry in m_certs)
            for (uint j = isReverse ? (uint)m_certsOrder.Count-1 : 0;
                 j < m_certsOrder.Count;
                 j = isReverse ? j-1 : j+1)
            {
                var certId = m_certsOrder[(int)j];
                var cert = m_certs[certId];
                // var certId = certEntry.Key;
                // var cert = certEntry.Value;

                if (m_keys.ContainsKey(certId))
                    continue;

                CertBag cBag = new CertBag(
                    PkcsObjectIdentifiers.X509Certificate,
                    new DerOctetString(cert.Certificate.GetEncoded()));

                Asn1EncodableVector fName = new Asn1EncodableVector();

                foreach (var oid in cert.BagAttributeKeys)
                {
                    // a certificate not immediately linked to a key doesn't require
                    // a localKeyID and will confuse some PKCS12 implementations.
                    //
                    // If we find one, we'll prune it out.
                    if (PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(oid))
                        continue;

                    // NB: Ignore any existing FriendlyName
                    if (!PkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(oid))
                    {
                        fName.Add(new DerSequence(oid, new DerSet(cert[oid])));
                    }
                }

                //
                // make sure we are using the local alias on store
                //
                // NB: We always set the FriendlyName based on 'certId'
                //if (cert[PkcsObjectIdentifiers.Pkcs9AtFriendlyName] == null)
                {
                    fName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                            new DerSet(new DerBmpString(certId))));
                }

                // the Oracle PKCS12 parser looks for a trusted key usage for named certificates as well
                if (cert[MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage] == null)
                {
                    Asn1OctetString ext = cert.Certificate.GetExtensionValue(X509Extensions.ExtendedKeyUsage);
          
                    if (ext != null)
                    {
                        ExtendedKeyUsage usage = ExtendedKeyUsage.GetInstance(ext.GetOctets());
                        IList<DerObjectIdentifier> usages = usage.GetAllUsages();
                        Asn1EncodableVector v = new Asn1EncodableVector(usages.Count);
                        for (int i = 0; i != usages.Count; i++)
                        {
                            v.Add(usages[i]);
                        }
                       
                        fName.Add(
                            new DerSequence(
                                MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage,
                                DerSet.FromVector(v)));
                    }
                    else
                    {
                        fName.Add(
                            new DerSequence(
                                MiscObjectIdentifiers.id_oracle_pkcs12_trusted_key_usage,
                                new DerSet(KeyPurposeID.AnyExtendedKeyUsage)));
                    }
                }

                certBags.Add(new SafeBag(PkcsObjectIdentifiers.CertBag, cBag.ToAsn1Object(), DerSet.FromVector(fName)));

                doneCerts.Add(cert.Certificate);
            }
            
            // foreach (var chainCertEntry in m_chainCerts)
            for (uint i = isReverse ? (uint)m_chainCertOrder.Count-1 : 0;
                 i < m_chainCertOrder.Count;
                 i = isReverse ? i-1 : i+1)
            {
                var certId = m_chainCertOrder[(int)i];
                var cert = m_chainCerts[certId];
                // var certId = chainCertEntry.Key;
                // var cert = chainCertEntry.Value;

                if (doneCerts.Contains(cert.Certificate))
                    continue;

                CertBag cBag = new CertBag(
                    PkcsObjectIdentifiers.X509Certificate,
                    new DerOctetString(cert.Certificate.GetEncoded()));

                Asn1EncodableVector fName = new Asn1EncodableVector();

                foreach (var oid in cert.BagAttributeKeys)
                {
                    // a certificate not immediately linked to a key doesn't require
                    // a localKeyID and will confuse some PKCS12 implementations.
                    //
                    // If we find one, we'll prune it out.
                    if (PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(oid))
                        continue;

                    fName.Add(new DerSequence(oid, new DerSet(cert[oid])));
                }

                certBags.Add(new SafeBag(PkcsObjectIdentifiers.CertBag, cBag.ToAsn1Object(), DerSet.FromVector(fName)));
            }

            byte[] certBagsEncoding = new DerSequence(certBags).GetDerEncoded();

            ContentInfo certsInfo;
            if (password == null || certAlgorithm == null)
            {
                certsInfo = new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(certBagsEncoding));
            }
            else
            {
                byte[] certBytes = CryptPbeData(true, cAlgId, password, false, certBagsEncoding);
                EncryptedData cInfo = new EncryptedData(PkcsObjectIdentifiers.Data, cAlgId, new BerOctetString(certBytes));
                certsInfo = new ContentInfo(PkcsObjectIdentifiers.EncryptedData, cInfo.ToAsn1Object());
            }

            ContentInfo[] info = new ContentInfo[]{ keysInfo, certsInfo };

            byte[] data = new AuthenticatedSafe(info).GetEncoded(
                useDerEncoding ? Asn1Encodable.Der : Asn1Encodable.Ber);

            ContentInfo mainInfo = new ContentInfo(PkcsObjectIdentifiers.Data, new BerOctetString(data));

            //
            // create the mac
            //
            MacData macData = null;
            if (password != null)
            {
                byte[] mSalt = new byte[20];
                random.NextBytes(mSalt);

                byte[] mac = CalculatePbeMac(OiwObjectIdentifiers.IdSha1,
                    mSalt, MinIterations, password, false, data);

                AlgorithmIdentifier algId = new AlgorithmIdentifier(
                    OiwObjectIdentifiers.IdSha1, DerNull.Instance);
                DigestInfo dInfo = new DigestInfo(algId, mac);

                macData = new MacData(dInfo, mSalt, MinIterations);
            }

            //
            // output the Pfx
            //
            Pfx pfx = new Pfx(mainInfo, macData);

            pfx.EncodeTo(stream, useDerEncoding ? Asn1Encodable.Der : Asn1Encodable.Ber);
        }

        internal static byte[] CalculatePbeMac(
            DerObjectIdentifier oid,
            byte[]              salt,
            int                 itCount,
            char[]              password,
            bool                wrongPkcs12Zero,
            byte[]              data)
        {
            Asn1Encodable asn1Params = PbeUtilities.GenerateAlgorithmParameters(
                oid, salt, itCount);
            ICipherParameters cipherParams = PbeUtilities.GenerateCipherParameters(
                oid, password, wrongPkcs12Zero, asn1Params);

            IMac mac = (IMac) PbeUtilities.CreateEngine(oid);
            mac.Init(cipherParams);
            return MacUtilities.DoFinal(mac, data);
        }

        private static byte[] CryptPbeData(
            bool                forEncryption,
            AlgorithmIdentifier algId,
            char[]              password,
            bool                wrongPkcs12Zero,
            byte[]              data)
        {
            IBufferedCipher cipher = PbeUtilities.CreateEngine(algId) as IBufferedCipher;

            if (cipher == null)
                throw new Exception("Unknown encryption algorithm: " + algId.Algorithm);

            if (algId.Algorithm.Equals(PkcsObjectIdentifiers.IdPbeS2))
            {
                PbeS2Parameters pbeParameters = PbeS2Parameters.GetInstance(algId.Parameters);
                ICipherParameters cipherParams = PbeUtilities.GenerateCipherParameters(
                    algId.Algorithm, password, pbeParameters);
                cipher.Init(forEncryption, cipherParams);
                return cipher.DoFinal(data);
            }
            else
            {
                Pkcs12PbeParams pbeParameters = Pkcs12PbeParams.GetInstance(algId.Parameters);
                ICipherParameters cipherParams = PbeUtilities.GenerateCipherParameters(
                    algId.Algorithm, password, wrongPkcs12Zero, pbeParameters);
                cipher.Init(forEncryption, cipherParams);
                return cipher.DoFinal(data);
            }
        }
    }
}
