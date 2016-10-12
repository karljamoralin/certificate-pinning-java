package com.karljamoralin.codesamples;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

/*Code sample for certificate pinning and authentication using a stored certificate. If server is not authenticated,
* an SSLHandshakeException will be thrown.*/

class SSLPinning {

    void exec() {

        // Open InputStreams for each certificate
        InputStream certStream = getClass().getResourceAsStream("cert.cer");

        try {

            // CertificateFactory has the method that generates certificates from InputStream
            // Default type for getInstance is X.509
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Create Certificate objects for each certificate
            Certificate certCertificate = cf.generateCertificate(certStream);

            // Create KeyStore and load it with our certificates
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("cert", certCertificate);

            // Create a TrustManagerFactory using KeyStore -- this is responsible in authenticating the servers
            // against our stored certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // Create an SSLContext using TrustManagerFactory -- this will generate the SSLSocketFactory we will use
            // during HTTPS connection
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), null);

            URL url = new URL("https://certs.cac.washington.edu/CAtest/");
            HttpsURLConnection httpsURLConnection = (HttpsURLConnection)url.openConnection();
            httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
            httpsURLConnection.connect();
            System.out.print("Server authentication successful");

        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SSLHandshakeException e) {
            e.printStackTrace();
            System.out.println("Server authentication failed");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }

    }

}
