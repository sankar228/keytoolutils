import org.apache.commons.cli.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class KeyToolUtils {

    static KeyStore keyStore;
    static String keyStorePath;
    static String storePassword;


    public static void main(String[] args) {
        String aliasName;
        String keyVal;
        /*mandatory fields*/
        Options options = new Options();
        options.addOption("ks", "keystore", true, "keystore file path")
                .addOption("sp", "storepass", true, "keystore password")
                .addOption("ka", "alias", true, "alias name / key name")
                .addOption("kv", "aliasval", true, "alias value / key value")
                .addOption("l", "list", false, "List all the keys from the keystore")
                .addOption("a", "set", false, "Add if the key does not exist or Set the existing key value, -ka and -kv are required")
                .addOption("d", "delete", false, "delete the existing key value, -ka required")
                .addOption("q", "query", false, "query key from keystore, -ka required")
                .addOption("h", "help", false, "keytoolutils CLI options");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
        if (!cmd.hasOption("ks") || cmd.hasOption("h")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("KeyToolUtils", options);
            if (!options.hasOption("ks")) {
                throw new RuntimeException("please pass the keystore file path");
            }
            System.exit(0);
        } else {
            keyStorePath = cmd.getOptionValue("ks");
            if (cmd.hasOption("sp")) {
                storePassword = cmd.getOptionValue("sp");
            }

            KeyToolUtils keyToolUtils = new KeyToolUtils();
            try {
                keyStore = keyToolUtils.loadKeyStore();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            try {
                /*optional fields*/
                if (cmd.hasOption("a")) {
                    aliasName = getAlias(cmd);
                    if (cmd.hasOption("kv")) {
                        keyVal = cmd.getOptionValue("kv");
                    } else {
                        throw new RuntimeException("key Value (-kv) is empty");
                    }

                    keyToolUtils.addKey(aliasName, keyVal);
                }
                if (cmd.hasOption("d")) {
                    aliasName = getAlias(cmd);
                    keyToolUtils.deleteKey(aliasName);
                }
                if (cmd.hasOption("l")) {
                    keyToolUtils.listEntries();
                }
                if (cmd.hasOption("q")) {
                    aliasName = getAlias(cmd);
                    System.out.println(aliasName + " ----> " +keyToolUtils.getKey(aliasName));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static String getAlias(CommandLine cmd) {
        if (cmd.hasOption("ka")) {
            return cmd.getOptionValue("ka");
        } else {
            throw new RuntimeException("[ka] alias option is required to add/set/delete the key in keystore");
        }
    }

    public KeyStore loadKeyStore() throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance("JCEKS");

        char[] keyStorePassword = storePassword.toCharArray();
        try (InputStream keyStoreData = new FileInputStream(keyStorePath)) {
            keyStore.load(keyStoreData, keyStorePassword);
        }

        return keyStore;
    }

    public void deleteKey(String aliasName) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        keyStore.deleteEntry(aliasName);
        try (OutputStream keyStoreOutput = new FileOutputStream(keyStorePath)) {
            keyStore.store(keyStoreOutput, storePassword.toCharArray());
        }
        System.out.println("key deleted from the keystore: " + aliasName);
    }

    public void addKey(String aliasName, String keyVal) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        SecretKey spec = new SecretKeySpec(keyVal.getBytes(), "PBEWithMD5AndDES");
        KeyStore.SecretKeyEntry secretKey = new KeyStore.SecretKeyEntry(spec);

        // Assuming entry and keystore have same password
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(storePassword.toCharArray());
        keyStore.deleteEntry(aliasName);
        keyStore.setEntry(aliasName, secretKey, entryPassword);

        try (OutputStream keyStoreOutput = new FileOutputStream(keyStorePath)) {
            keyStore.store(keyStoreOutput, storePassword.toCharArray());
        }
        System.out.println("keystore updated with new key: " + aliasName);
    }

    private String getKey(String aliasName) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {

        // Assuming entry and keystore have same password
        KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(storePassword.toCharArray());

        KeyStore.SecretKeyEntry keyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(aliasName, entryPassword);

        if(keyEntry == null){
            throw new RuntimeException("key not found in the keystore: "+aliasName);
        }
        return new String(keyEntry.getSecretKey().getEncoded());

    }

    private void listEntries() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableEntryException {
        Enumeration<String> aliases = keyStore.aliases();
        for (; aliases.hasMoreElements(); ) {
            String keyname = aliases.nextElement();
            String keyval = new String(((KeyStore.SecretKeyEntry) keyStore.getEntry(keyname, new KeyStore.PasswordProtection(storePassword.toCharArray()))).getSecretKey().getEncoded());
            System.out.println(keyname + " --> " + keyval);
        }
    }
}
