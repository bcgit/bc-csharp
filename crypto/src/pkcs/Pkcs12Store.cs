using System;
using System.Collections.Generic;
using System.IO;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Misc;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Operators.Utilities;
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
        private readonly List<string> m_keysOrder = new List<string>();

        private readonly Dictionary<string, string> m_localIds = new Dictionary<string, string>();

        private readonly Dictionary<string, X509CertificateEntry> m_certs =
            new Dictionary<string, X509CertificateEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> m_certsOrder = new List<string>();

        private readonly Dictionary<CertID, X509CertificateEntry> m_chainCerts =
            new Dictionary<CertID, X509CertificateEntry>();
        private readonly List<CertID> m_chainCertsOrder = new List<CertID>();

        private readonly Dictionary<string, X509CertificateEntry> m_keyCerts =
            new Dictionary<string, X509CertificateEntry>();

        private readonly DerObjectIdentifier keyAlgorithm;
        private readonly DerObjectIdentifier keyPrfAlgorithm;
        private readonly DerObjectIdentifier certAlgorithm;
        private readonly bool useDerEncoding;
        private readonly bool reverseCertificates;
        private readonly bool overwriteFriendlyName;

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
            DerObjectIdentifier certAlgorithm, bool useDerEncoding, bool reverseCertificates, bool overwriteFriendlyName)
        {
            this.keyAlgorithm = keyAlgorithm;
            this.keyPrfAlgorithm = keyPrfAlgorithm;
            this.certAlgorithm = certAlgorithm;
            this.useDerEncoding = useDerEncoding;
            this.reverseCertificates = reverseCertificates;
            this.overwriteFriendlyName = overwriteFriendlyName;
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

                        if (PkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(aOid))
                        {
                            alias = ((DerBmpString)attr).GetString();
                            // TODO Do these in a separate loop, just collect aliases here
                            Map(m_keys, m_keysOrder, alias, keyEntry);
                        }
                        else if (PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(aOid))
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
                    Map(m_keys, m_keysOrder, name, keyEntry);
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
                throw new ArgumentNullException(nameof(input));

            Pfx pfx = Pfx.GetInstance(Asn1Object.FromStream(input));
            ContentInfo info = pfx.AuthSafe;
            bool wrongPkcs12Zero = false;

            var macData = pfx.MacData;
            if (macData != null) // check the mac code
            {
                if (password == null)
                    throw new ArgumentNullException(nameof(password), "no password supplied when one expected");

                byte[] data = Asn1OctetString.GetInstance(info.Content).GetOctets();

                if (!VerifyPbeMac(macData, password, wrongPkcs12Zero: false, data))
                {
                    // Try with incorrect zero length password conversion
                    if (password.Length == 0 && VerifyPbeMac(macData, password, wrongPkcs12Zero: true, data))
                    {
                        wrongPkcs12Zero = true;
                    }
                    else
                    {
                        throw new IOException("PKCS12 key store MAC invalid - wrong password or corrupted file.");
                    }
                }
            }
            else if (password != null)
            {
                string ignoreProperty = Platform.GetEnvironmentVariable(IgnoreUselessPasswordProperty);
                bool ignore = ignoreProperty != null && Platform.EqualsIgnoreCase("true", ignoreProperty);

                if (!ignore)
                    throw new IOException("password supplied for keystore that does not require one");
            }

            Clear(m_keys, m_keysOrder);
            m_localIds.Clear();
            unmarkedKeyEntry = null;

            var certBags = new List<SafeBag>();

            if (PkcsObjectIdentifiers.Data.Equals(info.ContentType))
            {
                Asn1OctetString content = Asn1OctetString.GetInstance(info.Content);
                AuthenticatedSafe authSafe = AuthenticatedSafe.GetInstance(content.GetOctets());
                ContentInfo[] cis = authSafe.GetContentInfo();

                foreach (ContentInfo ci in cis)
                {
                    DerObjectIdentifier oid = ci.ContentType;

                    byte[] octets = null;
                    if (PkcsObjectIdentifiers.Data.Equals(oid))
                    {
                        octets = Asn1OctetString.GetInstance(ci.Content).GetOctets();
                    }
                    else if (PkcsObjectIdentifiers.EncryptedData.Equals(oid))
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

                            if (PkcsObjectIdentifiers.CertBag.Equals(b.BagID))
                            {
                                certBags.Add(b);
                            }
                            else if (PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag.Equals(b.BagID))
                            {
                                LoadPkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo.GetInstance(b.BagValue),
                                    b.BagAttributes, password, wrongPkcs12Zero);
                            }
                            else if (PkcsObjectIdentifiers.KeyBag.Equals(b.BagID))
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

            Clear(m_certs, m_certsOrder);
            Clear(m_chainCerts, m_chainCertsOrder);
            m_keyCerts.Clear();

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

                            if (PkcsObjectIdentifiers.Pkcs9AtFriendlyName.Equals(aOid))
                            {
                                alias = ((DerBmpString)attr).GetString();
                            }
                            else if (PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(aOid))
                            {
                                localId = (Asn1OctetString)attr;
                            }
                        }
                    }
                }

                CertID certID = new CertID(cert);
                X509CertificateEntry certEntry = new X509CertificateEntry(cert, attributes);
                Map(m_chainCerts, m_chainCertsOrder, certID, certEntry);

                if (unmarkedKeyEntry != null)
                {
                    if (m_keyCerts.Count == 0)
                    {
                        string name = Hex.ToHexString(certID.ID);

                        m_keyCerts[name] = certEntry;
                        Map(m_keys, m_keysOrder, name, unmarkedKeyEntry);
                    }
                    else
                    {
                        Map(m_keys, m_keysOrder, "unmarked", unmarkedKeyEntry);
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
                        Map(m_certs, m_certsOrder, alias, certEntry);
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

            Map(m_certs, m_certsOrder, alias, certEntry);
            Map(m_chainCerts, m_chainCertsOrder, new CertID(certEntry), certEntry);
        }

        public void SetFriendlyName(string alias, String newFriendlyName)
        {
            if (alias.Equals(newFriendlyName) || overwriteFriendlyName)
            {
                return;
            }

            if (IsKeyEntry(alias))
            {
                AsymmetricKeyEntry keyEntry = GetKey(alias);
                X509CertificateEntry keyCertEntry = GetCertificate(alias);
                keyEntry.SetFriendlyName(newFriendlyName);
                m_keys.Add(newFriendlyName, keyEntry);
                m_keys.Remove(alias);
                m_keysOrder.Add(newFriendlyName);
                m_keysOrder.Remove(alias);

                keyCertEntry.SetFriendlyName(newFriendlyName);
                m_keyCerts.Add(newFriendlyName, keyCertEntry);
                m_keyCerts.Remove(alias);

            }

            if (IsCertificateEntry(alias))
            {
                X509CertificateEntry certEntry = GetCertificate(alias);
                certEntry.SetFriendlyName(newFriendlyName);
                m_certs.Add(newFriendlyName, certEntry);
                m_certs.Remove(alias);
                m_certsOrder.Add(newFriendlyName);
                m_certsOrder.Remove(alias);
            }
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

            Map(m_keys, m_keysOrder, alias, keyEntry);

            if (chain.Length > 0)
            {
                Map(m_certs, m_certsOrder, alias, chain[0]);

                foreach (var certificateEntry in chain)
                {
                    Map(m_chainCerts, m_chainCertsOrder, new CertID(certificateEntry), certificateEntry);
                }
            }
        }

        public void DeleteEntry(string alias)
        {
            if (alias == null)
                throw new ArgumentNullException(nameof(alias));

            if (Remove(m_certs, m_certsOrder, alias, out var certEntry))
            {
                Remove(m_chainCerts, m_chainCertsOrder, new CertID(certEntry));
            }

            if (Remove(m_keys, m_keysOrder, alias))
            {
                if (CollectionUtilities.Remove(m_localIds, alias, out var id))
                {
                    if (CollectionUtilities.Remove(m_keyCerts, id, out var keyCertEntry))
                    {
                        Remove(m_chainCerts, m_chainCertsOrder, new CertID(keyCertEntry));
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
            for (uint i = reverseCertificates ? (uint)m_keysOrder.Count-1 : 0;
                 i < m_keysOrder.Count;
                 i = reverseCertificates ? i-1 : i+1)
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
                    if (overwriteFriendlyName)
                    {
                        kName.Add(
                            new DerSequence(
                                PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                                new DerSet(new DerBmpString(name))));
                    }
                    else 
                    {
                        DerSet friendlyName = DerSet.Empty;
                        if(privKey.HasFriendlyName)
                        {
                            friendlyName = new DerSet(privKey[PkcsObjectIdentifiers.Pkcs9AtFriendlyName]);
                        }
                        kName.Add(
                            new DerSequence(
                                PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                                friendlyName));
                    }
                   
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

            for (uint i = reverseCertificates ? (uint)m_keysOrder.Count-1 : 0;
                 i < m_keysOrder.Count;
                 i = reverseCertificates ? i-1 : i+1)
            {
                string name = m_keysOrder[(int)i];
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
                if(overwriteFriendlyName)
                {
                    fName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                            new DerSet(new DerBmpString(name))));
                }
                else
                {
                    DerSet friendlyName = DerSet.Empty;
                    if(certEntry.HasFriendlyName)
                    {
                        friendlyName = new DerSet(certEntry[PkcsObjectIdentifiers.Pkcs9AtFriendlyName]);
                    }
                    fName.Add(
                            new DerSequence(
                                PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                                friendlyName));
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

            for (uint j = reverseCertificates ? (uint)m_certsOrder.Count-1 : 0;
                 j < m_certsOrder.Count;
                 j = reverseCertificates ? j-1 : j+1)
            {
                var alias = m_certsOrder[(int)j];
                var cert = m_certs[alias];

                if (m_keys.ContainsKey(alias))
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
                if(overwriteFriendlyName)
                {
                    fName.Add(
                        new DerSequence(
                            PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                            new DerSet(new DerBmpString(alias))));
                }
                else
                {
                    DerSet friendlyName = DerSet.Empty;
                    if(cert.HasFriendlyName)
                    {
                        friendlyName = new DerSet(cert[PkcsObjectIdentifiers.Pkcs9AtFriendlyName]);
                    }
                    fName.Add(
                            new DerSequence(
                                PkcsObjectIdentifiers.Pkcs9AtFriendlyName,
                                friendlyName));
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

            for (uint i = reverseCertificates ? (uint)m_chainCertsOrder.Count-1 : 0;
                 i < m_chainCertsOrder.Count;
                 i = reverseCertificates ? i-1 : i+1)
            {
                CertID certID = m_chainCertsOrder[(int)i];
                X509CertificateEntry certEntry = m_chainCerts[certID];
                X509Certificate cert = certEntry.Certificate;

                if (doneCerts.Contains(cert))
                    continue;

                CertBag cBag = new CertBag(
                    PkcsObjectIdentifiers.X509Certificate,
                    new DerOctetString(cert.GetEncoded()));

                Asn1EncodableVector fName = new Asn1EncodableVector();

                foreach (var oid in certEntry.BagAttributeKeys)
                {
                    // a certificate not immediately linked to a key doesn't require
                    // a localKeyID and will confuse some PKCS12 implementations.
                    //
                    // If we find one, we'll prune it out.
                    if (PkcsObjectIdentifiers.Pkcs9AtLocalKeyID.Equals(oid))
                        continue;

                    fName.Add(new DerSequence(oid, new DerSet(certEntry[oid])));
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
                // TODO Support other HMAC digest algorithms (SHA-224, SHA-256, SHA384, SHA-512, SHA-512/224,
                // or SHA-512/256) and PBMAC1 (RFC 9579).
                var macDigestAlgorithm = DefaultDigestAlgorithmFinder.Instance.Find(OiwObjectIdentifiers.IdSha1);
                // TODO Configurable salt length?
                byte[] salt = SecureRandom.GetNextBytes(random, 20);
                // TODO Configurable number of iterations
                int itCount = MinIterations;

                byte[] macResult = CalculatePbeMac(macDigestAlgorithm, salt, itCount, password, wrongPkcs12Zero: false,
                    data);

                var mac = new DigestInfo(macDigestAlgorithm, new DerOctetString(macResult));

                macData = new MacData(mac, salt, itCount);
            }

            //
            // output the Pfx
            //
            Pfx pfx = new Pfx(mainInfo, macData);

            pfx.EncodeTo(stream, useDerEncoding ? Asn1Encodable.Der : Asn1Encodable.Ber);
        }

        internal static byte[] CalculatePbeMac(AlgorithmIdentifier macDigestAlgorithm, byte[] salt, int iterations,
            char[] password, bool wrongPkcs12Zero, byte[] data)
        {
            // TODO Convert to HMAC algorithm here (restrict valid digest OIDs) instead of PbeUtilities doing it
            // TODO Support PBMAC1
            var hmacDigestOid = macDigestAlgorithm.Algorithm;
            var pbeParameters = PbeUtilities.GenerateAlgorithmParameters(hmacDigestOid, salt, iterations);
            var cipherParameters = PbeUtilities.GenerateCipherParameters(hmacDigestOid, password, wrongPkcs12Zero,
                pbeParameters);

            IMac mac = (IMac)PbeUtilities.CreateEngine(hmacDigestOid);
            mac.Init(cipherParameters);
            return MacUtilities.DoFinal(mac, data);
        }

        internal static bool VerifyPbeMac(MacData macData, char[] password, bool wrongPkcs12Zero, byte[] data)
        {
            DigestInfo mac = macData.Mac;
            byte[] macResult = CalculatePbeMac(mac.DigestAlgorithm, macData.MacSalt.GetOctets(),
                macData.Iterations.IntValueExact, password, wrongPkcs12Zero, data);
            return Arrays.FixedTimeEquals(macResult, mac.Digest.GetOctets());
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

            if (PkcsObjectIdentifiers.IdPbeS2.Equals(algId.Algorithm))
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

        private static void Clear<K, V>(Dictionary<K, V> d, List<K> o)
        {
            d.Clear();
            o.Clear();
        }

        private static void Map<K, V>(Dictionary<K, V> d, List<K> o, K k, V v)
        {
            if (d.ContainsKey(k))
            {
                RemoveOrdering(d.Comparer, o, k);
            }

            o.Add(k);
            d[k] = v;
        }

        private static bool Remove<K, V>(Dictionary<K, V> d, List<K> o, K k)
        {
            bool result = d.Remove(k);
            if (result)
            {
                RemoveOrdering(d.Comparer, o, k);
            }
            return result;
        }

        private static bool Remove<K, V>(Dictionary<K, V> d, List<K> o, K k, out V v)
        {
            bool result = CollectionUtilities.Remove(d, k, out v);
            if (result)
            {
                RemoveOrdering(d.Comparer, o, k);
            }
            return result;
        }

        private static void RemoveOrdering<K>(IEqualityComparer<K> c, List<K> o, K k)
        {
            int index = o.FindIndex(e => c.Equals(k, e));
            if (index >= 0)
            {
                o.RemoveAt(index);
            }
        }
    }
}
