import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Scanner;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLSession;

public class TLSAnalyzer {
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter hostname: ");
        String host = scanner.nextLine().trim();

        analyzeTLS(host);

        scanner.close();
    
    }

    public static void analyzeTLS(String host) {

        int port = 443;

        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

            SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

            socket.startHandshake();

            SSLSession session = socket.getSession();

            X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];

            System.out.println("\n--- TLS Security Report ---\n");

            //TLS Version Check
            String protocol = session.getProtocol();

            if (protocol.equals("TLSv1.3")) {
                System.out.println("[PASS] TLS Version: " + protocol);
            } else if (protocol.equals("TLSv1.2")) {
                System.out.println("[WARN] TLS Version: " + protocol);
            } else {
                System.out.println("[FAIL] Outdates TLS Version: " + protocol);
            }

            // Certificate Validity Check
            try {
                cert.checkValidity();
                System.out.println("[PASS] Certificate is currently valid");
            } catch (Exception e) {
                System.out.println("[FAIL] Certificate is invalid or expired.");
            }

            // Expiration Check
            Date expiration = cert.getNotAfter();

            long millisRemaining = expiration.getTime() - System.currentTimeMillis();

            long daysRemaining = millisRemaining / (1000L * 60 * 60 * 24);

            if (daysRemaining < 0) {
                System.out.println("[FAIL] Certificate expired");
            } else if (daysRemaining < 30) {
                System.out.println("[WARN] Certificate expires in " + daysRemaining + " days");
            } else {
                System.out.println("[PASS] Certificate expires in " + daysRemaining + " days");
            }

            //Informational Details
            System.out.println("[INFO] Cipher Suite: " + session.getCipherSuite());
            System.out.println("[INFO] Issuer: " + cert.getIssuerX500Principal().getName());
            System.out.println("\nScan Complete.");

            socket.close();

        }
        catch (Exception e) {
            System.out.println("\nFailed to analyze host: " + host);
        }
    }
}
