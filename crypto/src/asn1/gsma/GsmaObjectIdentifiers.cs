namespace Org.BouncyCastle.Asn1.Gsma
{
    public static class GsmaObjectIdentifiers
    {
        public static readonly DerObjectIdentifier id_gsma = new DerObjectIdentifier("2.23.146");

        public static readonly DerObjectIdentifier id_rsp = id_gsma.Branch("1");

        public static readonly DerObjectIdentifier id_rsp_cert_objects = id_rsp.Branch("2");

        public static readonly DerObjectIdentifier id_rspExt = id_rsp_cert_objects.Branch("0");

        public static readonly DerObjectIdentifier id_rsp_expDate = id_rspExt.Branch("1");
        public static readonly DerObjectIdentifier id_rsp_totalPartialCrlNumber = id_rspExt.Branch("2");
        public static readonly DerObjectIdentifier id_rsp_partialCrlNumber = id_rspExt.Branch("3");

        public static readonly DerObjectIdentifier id_rspRole = id_rsp_cert_objects.Branch("1");

        public static readonly DerObjectIdentifier id_rspRole_ci = id_rspRole.Branch("0");
        public static readonly DerObjectIdentifier id_rspRole_euicc = id_rspRole.Branch("1");
        public static readonly DerObjectIdentifier id_rspRole_eum = id_rspRole.Branch("2");
        public static readonly DerObjectIdentifier id_rspRole_dp_tls = id_rspRole.Branch("3");
        public static readonly DerObjectIdentifier id_rspRole_dp_auth = id_rspRole.Branch("4");
        public static readonly DerObjectIdentifier id_rspRole_dp_pb = id_rspRole.Branch("5");
        public static readonly DerObjectIdentifier id_rspRole_ds_tls = id_rspRole.Branch("6");
        public static readonly DerObjectIdentifier id_rspRole_ds_auth = id_rspRole.Branch("7");

        public static readonly DerObjectIdentifier id_rsp_metadata = id_rsp.Branch("3");

        public static readonly DerObjectIdentifier id_rsp_metadata_serviceSpecificOIDs = id_rsp_metadata.Branch("1");

        public static readonly DerObjectIdentifier id_rsp_metadata_activationCodeRetrievalInfo =
            id_rsp_metadata_serviceSpecificOIDs.Branch("1");
    }
}
