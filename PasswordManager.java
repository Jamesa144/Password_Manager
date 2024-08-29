import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;

/**
 * A simple Password Manager application that allows users to store, encrypt,
 * and view passwords after verifying the master password.
 */
public class PasswordManager extends JFrame {
    // List to store password entries
    private ArrayList<PasswordEntry> passwords;
    
    // GUI components for input fields and display area
    private JTextField labelField, passwordField;
    private JTextArea displayArea;
    
    // Master password for encrypting/decrypting passwords
    private String masterPassword;

    // Constructor to initialize the password list and setup the GUI
    public PasswordManager() {
        passwords = new ArrayList<>();
        setupGUI();
    }

    /**
     * Sets up the graphical user interface.
     */
    private void setupGUI() {
        setTitle("Password Manager");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        // Panel to hold input fields and buttons
        JPanel inputPanel = new JPanel(new GridLayout(4, 2));
        
        inputPanel.add(new JLabel("Label:"));
        labelField = new JTextField();
        inputPanel.add(labelField);

        inputPanel.add(new JLabel("Password:"));
        passwordField = new JTextField();
        inputPanel.add(passwordField);

        // Button to add a new password
        JButton addButton = new JButton("Add Password");
        addButton.addActionListener(e -> addPassword());
        inputPanel.add(addButton);

        // Button to set the master password
        JButton setMasterPasswordButton = new JButton("Set Master Password");
        setMasterPasswordButton.addActionListener(e -> setMasterPassword());
        inputPanel.add(setMasterPasswordButton);

        // Button to show all stored passwords (after verifying master password)
        JButton showButton = new JButton("Show Passwords");
        showButton.addActionListener(e -> showPasswords());
        inputPanel.add(showButton);

        // Text area to display stored passwords
        displayArea = new JTextArea();
        displayArea.setEditable(false);

        // Adding components to the main frame
        add(inputPanel, BorderLayout.NORTH);
        add(new JScrollPane(displayArea), BorderLayout.CENTER);
    }

    /**
     * Prompts the user to set a master password. This password will be used for
     * encrypting and decrypting stored passwords.
     */
    private void setMasterPassword() {
        if (masterPassword == null) {
            masterPassword = JOptionPane.showInputDialog(this, "Set your master password:");
            if (masterPassword != null && !masterPassword.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Master password set successfully!");
            } else {
                masterPassword = null;
                JOptionPane.showMessageDialog(this, "Master password cannot be empty.");
            }
        } else {
            JOptionPane.showMessageDialog(this, "Master password is already set.");
        }
    }

    /**
     * Adds a new password entry after encrypting it using the master password.
     */
    private void addPassword() {
        if (masterPassword == null) {
            JOptionPane.showMessageDialog(this, "Please set a master password first.");
            return;
        }

        String label = labelField.getText();
        String password = passwordField.getText();
        if (!label.isEmpty() && !password.isEmpty()) {
            // Encrypt the password before storing it
            passwords.add(new PasswordEntry(label, encrypt(password)));
            labelField.setText("");
            passwordField.setText("");
            JOptionPane.showMessageDialog(this, "Password added successfully!");
        } else {
            JOptionPane.showMessageDialog(this, "Please enter both label and password.");
        }
    }

    /**
     * Displays all stored passwords after verifying the master password.
     */
    private void showPasswords() {
        if (masterPassword == null) {
            JOptionPane.showMessageDialog(this, "Please set a master password first.");
            return;
        }

        String enteredPassword = JOptionPane.showInputDialog(this, "Enter master password:");
        if (enteredPassword != null && enteredPassword.equals(masterPassword)) {
            StringBuilder sb = new StringBuilder();
            for (PasswordEntry entry : passwords) {
                // Decrypt the password before displaying it
                sb.append(entry.getLabel()).append(": ")
                  .append(decrypt(entry.getEncryptedPassword())).append("\n");
            }
            displayArea.setText(sb.toString());
        } else {
            JOptionPane.showMessageDialog(this, "Incorrect master password.");
        }
    }

    /**
     * Encrypts the given password using AES encryption and the master password.
     *
     * @param password The plain text password to encrypt.
     * @return The encrypted password as a Base64 encoded string.
     */
    private String encrypt(String password) {
        try {
            SecretKey key = generateKey(masterPassword);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedBytes = cipher.doFinal(password.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts the given encrypted password using AES decryption and the master password.
     *
     * @param encryptedPassword The Base64 encoded encrypted password to decrypt.
     * @return The decrypted plain text password.
     */
    private String decrypt(String encryptedPassword) {
        try {
            SecretKey key = generateKey(masterPassword);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedPassword));
            return new String(decryptedBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generates a SecretKey for AES encryption/decryption based on the master password.
     *
     * @param password The master password used to generate the key.
     * @return The generated SecretKey.
     * @throws Exception if the key generation fails.
     */
    private SecretKey generateKey(String password) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), "salt".getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    // Main method to run the Password Manager application
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new PasswordManager().setVisible(true));
    }
}

/**
 * Represents an individual password entry with a label and an encrypted password.
 */
class PasswordEntry {
    private String label;
    private String encryptedPassword;

    // Constructor to create a new password entry
    public PasswordEntry(String label, String encryptedPassword) {
        this.label = label;
        this.encryptedPassword = encryptedPassword;
    }

    // Getter for the label
    public String getLabel() {
        return label;
    }

    // Getter for the encrypted password
    public String getEncryptedPassword() {
        return encryptedPassword;
    }
}
