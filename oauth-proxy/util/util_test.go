package util

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/bmizerany/assert"
)

var (
	testCA1Subj = "301e311c301a060355040313136f617574682d70726f78792074657374206361"
	testCA1     = `-----BEGIN CERTIFICATE-----
MIICuTCCAaGgAwIBAgIFAKuKEWowDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAxMT
b2F1dGgtcHJveHkgdGVzdCBjYTAeFw0xNzEwMjQyMDExMzJaFw0xOTEwMjQyMDEx
MzJaMB4xHDAaBgNVBAMTE29hdXRoLXByb3h5IHRlc3QgY2EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC5/kmgKNiECuxlj27yTWBWOMVvIB0AaRhQrMA7
3iSCk/SHhaTabUuXUGRwmCAewT/y9oX3rTdfnSPCn7praU/27lRFBgOGFrTzAZH6
voisF54I3ZxWZgHDJ/ig/KFwd0Y8OATj9/k9uAJSCe6aT7BouJPZVWNGF2dF5BOJ
EwFsJiN2s8HpF14DhxFOMMtlckdMHGxi3wj3E/hBCfGvGGU4Wezz48vEWWC1ajWM
qVq2vVWi1bcNft8FjWa5wTGpdlDQJM7yvKYJPwRkEjgIXtF1ra3JM3WTTFZO9Yhd
QXwO7IWRTdTaypKTNbTDKuWQZsm7xQM9sNcFkukGb3o+uBpLAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAHJNrUfHhN7VOUF60pG8sOEkx0ztjbtbYMj2N9Kb0oSya+re
Kmb2Z4JgyV7XHCZ03Jch6L7UBI3Y6/Lp1zdwU03LFayVUchLkvFonoXpRRP5UFYN
+36xP3ZL1qBYFphARsCk6/tl36czH4oF5gTlhWCRy3upNzn+INk467hnCKt5xuse
zhm+xQv/VN1poI0S/oCg9HLA9iKpoqGJByN32yoFr3QViLPqkmJ1v8EiH0Ns+1m3
pP5YlVqdRCVrxgT80PIMsvQhfcuIrbbeiRDEUdEX7FqebuGCEa2757MTdW7UYQiB
7kgECMnwAOlJME8aDKnmTBajaMy6xCSC87V7wps=
-----END CERTIFICATE-----
`
	testCA2Subj = "3025312330210603550403131a6f617574682d70726f7879207365636f6e642074657374206361"
	testCA2     = `-----BEGIN CERTIFICATE-----
MIICxzCCAa+gAwIBAgIFAKuMKewwDQYJKoZIhvcNAQELBQAwJTEjMCEGA1UEAxMa
b2F1dGgtcHJveHkgc2Vjb25kIHRlc3QgY2EwHhcNMTcxMDI1MTYxMTQxWhcNMTkx
MDI1MTYxMTQxWjAlMSMwIQYDVQQDExpvYXV0aC1wcm94eSBzZWNvbmQgdGVzdCBj
YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKdTkEOJ+QpOHy0PqGDR
fu8NFyo7BJwAnI+P1G32UXMeecCwBgGJEyv6eHEFV6jH/U2K2H0hynaCFxRuIdTA
EeS4s4BAbKqFhQ62I9lF3HVuqRPOe5FYdUl80eQynME22fWQ6/sZdQds0sFqaJBz
R4KQQxVULT19Br/6zwQZZhC1NtzSwCqi4CoO2OM7ctUKRvtC87LNGWapz5I4eh0A
/q4XJaSObsBCAJD7OVMa1LM3sSINUnvvGoSBKTuJ8MRk/BQRAO/PwXxsa+2h+k+w
D6sLExrBgWzAAPQKRKF+nLYVhz9AKn4JBpZt9j4PvTKz1SDcJ5wVEzOfVmii7Ui3
EFcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAiy58XvhOka3drXv2bwl95FwNtodj
L2MmIdF0pp01O0ryREcC1kogamdOS/UHQs4okuCjwinR/UgU+cFGCDYHfeENtUTw
Ox2OikYD7bXUpNzbQ4QyF0+cKwAgxD4ai5xSV/NUvMkL1aE8tLyxGm6VkhhyvxU1
U9kvLha6KBWOCNd2fBJxgg8RAxFV3vR+xLdEtXnBAeTURrHM19gwMtd16y6gUZTZ
Xbl3Ix0t2+sqi0hpEF/iVFdCp5TXiicSnZCtePzCfHePAEfbh5hS0bq8Lbb9DZ6d
+2jX3AVuYhQPuutxla+vNp2XRcMTbzwXyi/Ig4nHKmPLFXsEbv+4tSwxyQ==
-----END CERTIFICATE-----
`
)

func makeTestCertFile(t *testing.T, pem, dir string) *os.File {
	file, err := ioutil.TempFile(dir, "test-certfile")
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	_, err = file.Write([]byte(pem))
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}
	return file
}

func TestGetCertPool(t *testing.T) {
	_, err := GetCertPool([]string(nil), false)
	if err == nil {
		t.Errorf("expected an error")
	}
	assert.Equal(t, "Invalid empty list of Root CAs file paths", err.Error())

	tempDir := t.TempDir()
	certFile1 := makeTestCertFile(t, testCA1, tempDir)
	certFile2 := makeTestCertFile(t, testCA2, tempDir)

	certPool, err := GetCertPool([]string{certFile1.Name(), certFile2.Name()}, false)
	if err != nil {
		t.Errorf("unexpected error %v", err)
	}

	subj := certPool.Subjects()
	var got []string
	for i := range subj {
		got = append(got, hex.EncodeToString(subj[i]))
	}

	expectedSubjects := []string{testCA1Subj, testCA2Subj}
	if !reflect.DeepEqual(expectedSubjects, got) {
		t.Errorf("expected %v, got %v", expectedSubjects, subj)
	}
}
