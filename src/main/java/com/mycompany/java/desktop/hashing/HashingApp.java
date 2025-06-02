package com.mycompany.java.desktop.hashing;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;

public class HashingApp extends JFrame {
    private JTextArea inputTextArea;
    private JTextArea outputTextArea;
    private JTextField filePathField;
    private JComboBox<String> algorithmCombo;
    private JSpinner iterationsSpinner;
    private JSpinner saltLengthSpinner;
    private JSpinner costSpinner;
    private JCheckBox useCustomSaltCheck;
    private JTextField customSaltField;
    private JProgressBar progressBar;
    private JLabel costLabel;
    
    private static final String[] ALGORITHMS = {"PBKDF2", "BCrypt", "SCrypt"};
    
    public HashingApp() {
        initializeComponents();
        setupLayout();
        setupEventHandlers();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setTitle("Aplikasi Hashing - PBKDF2, BCrypt, SCrypt (Native Implementation)");
        setSize(850, 750);
        setLocationRelativeTo(null);
    }
    
    private void initializeComponents() {
        // Input components
        inputTextArea = new JTextArea(5, 40);
        inputTextArea.setLineWrap(true);
        inputTextArea.setWrapStyleWord(true);
        inputTextArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        // Output components
        outputTextArea = new JTextArea(10, 40);
        outputTextArea.setLineWrap(true);
        outputTextArea.setWrapStyleWord(true);
        outputTextArea.setEditable(false);
        outputTextArea.setBackground(Color.LIGHT_GRAY);
        outputTextArea.setBorder(BorderFactory.createLoweredBevelBorder());
        
        // File selection
        filePathField = new JTextField(30);
        filePathField.setEditable(false);
        
        // Algorithm selection
        algorithmCombo = new JComboBox<>(ALGORITHMS);
        algorithmCombo.setSelectedIndex(0);
        
        // Parameters
        iterationsSpinner = new JSpinner(new SpinnerNumberModel(10000, 1000, 100000, 1000));
        saltLengthSpinner = new JSpinner(new SpinnerNumberModel(16, 8, 64, 8));
        costSpinner = new JSpinner(new SpinnerNumberModel(12, 4, 31, 1));
        costLabel = new JLabel("Cost/Rounds:");
        
        // Custom salt
        useCustomSaltCheck = new JCheckBox("Gunakan Salt Kustom");
        customSaltField = new JTextField(20);
        customSaltField.setEnabled(false);
        
        // Progress bar
        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("Siap");
    }
    
    private void setupLayout() {
        setLayout(new BorderLayout());
        
        // Main panel
        JPanel mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Top panel - Input section
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBorder(new TitledBorder("Input"));
        
        // Text input
        JPanel textInputPanel = new JPanel(new BorderLayout());
        textInputPanel.add(new JLabel("Teks untuk di-hash:"), BorderLayout.NORTH);
        textInputPanel.add(new JScrollPane(inputTextArea), BorderLayout.CENTER);
        
        // File input
        JPanel fileInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileInputPanel.add(new JLabel("Atau pilih file:"));
        fileInputPanel.add(filePathField);
        JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(e -> browseFile());
        fileInputPanel.add(browseButton);
        
        topPanel.add(textInputPanel, BorderLayout.CENTER);
        topPanel.add(fileInputPanel, BorderLayout.SOUTH);
        
        // Middle panel - Configuration
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(new TitledBorder("Konfigurasi"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        configPanel.add(new JLabel("Algoritma:"), gbc);
        gbc.gridx = 1;
        configPanel.add(algorithmCombo, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1;
        configPanel.add(new JLabel("Iterasi/N:"), gbc);
        gbc.gridx = 1;
        configPanel.add(iterationsSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2;
        configPanel.add(costLabel, gbc);
        gbc.gridx = 1;
        configPanel.add(costSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3;
        configPanel.add(new JLabel("Panjang Salt:"), gbc);
        gbc.gridx = 1;
        configPanel.add(saltLengthSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 2;
        configPanel.add(useCustomSaltCheck, gbc);
        
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 1;
        configPanel.add(new JLabel("Salt Kustom:"), gbc);
        gbc.gridx = 1;
        configPanel.add(customSaltField, gbc);
        
        // Buttons panel
        JPanel buttonsPanel = new JPanel(new FlowLayout());
        JButton hashButton = new JButton("Hash");
        JButton clearButton = new JButton("Clear");
        JButton copyButton = new JButton("Copy Result");
        
        hashButton.addActionListener(e -> performHashing());
        clearButton.addActionListener(e -> clearAll());
        copyButton.addActionListener(e -> copyResult());
        
        buttonsPanel.add(hashButton);
        buttonsPanel.add(clearButton);
        buttonsPanel.add(copyButton);
        
        // Bottom panel - Output
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.setBorder(new TitledBorder("Hasil Hash"));
        bottomPanel.add(new JScrollPane(outputTextArea), BorderLayout.CENTER);
        
        // Status panel
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.add(progressBar, BorderLayout.CENTER);
        
        // Add all panels
        mainPanel.add(topPanel, BorderLayout.NORTH);
        mainPanel.add(configPanel, BorderLayout.CENTER);
        mainPanel.add(buttonsPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
        add(bottomPanel, BorderLayout.SOUTH);
        add(statusPanel, BorderLayout.PAGE_END);
    }
    
    private void setupEventHandlers() {
        useCustomSaltCheck.addActionListener(e -> {
            customSaltField.setEnabled(useCustomSaltCheck.isSelected());
            saltLengthSpinner.setEnabled(!useCustomSaltCheck.isSelected());
        });
        
        algorithmCombo.addActionListener(e -> updateParameterVisibility());
        updateParameterVisibility(); // Initial setup
    }
    
    private void updateParameterVisibility() {
        String selected = (String) algorithmCombo.getSelectedItem();
        
        switch (selected) {
            case "PBKDF2":
                iterationsSpinner.setEnabled(true);
                costSpinner.setEnabled(false);
                costLabel.setText("Cost/Rounds:");
                break;
            case "BCrypt":
                iterationsSpinner.setEnabled(false);
                costSpinner.setEnabled(true);
                costLabel.setText("Cost (4-31):");
                break;
            case "SCrypt":
                iterationsSpinner.setEnabled(true);
                costSpinner.setEnabled(true);
                costLabel.setText("r parameter:");
                break;
        }
    }
    
    private void browseFile() {
        JFileChooser fileChooser = new JFileChooser();
        if (fileChooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            filePathField.setText(selectedFile.getAbsolutePath());
        }
    }
    
    private void performHashing() {
        SwingWorker<String, Integer> worker = new SwingWorker<String, Integer>() {
            @Override
            protected String doInBackground() throws Exception {
                progressBar.setString("Memproses...");
                progressBar.setIndeterminate(true);
                
                String input = getInput();
                if (input == null || input.trim().isEmpty()) {
                    return "Error: Input kosong";
                }
                
                String algorithm = (String) algorithmCombo.getSelectedItem();
                
                switch (algorithm) {
                    case "PBKDF2":
                        return hashWithPBKDF2(input);
                    case "BCrypt":
                        return hashWithBCrypt(input);
                    case "SCrypt":
                        return hashWithSCrypt(input);
                    default:
                        return "Error: Algoritma tidak dikenal";
                }
            }
            
            @Override
            protected void done() {
                try {
                    String result = get();
                    outputTextArea.setText(result);
                    progressBar.setString("Selesai");
                } catch (Exception e) {
                    outputTextArea.setText("Error: " + e.getMessage());
                    progressBar.setString("Error");
                } finally {
                    progressBar.setIndeterminate(false);
                }
            }
        };
        
        worker.execute();
    }
    
    private String getInput() throws IOException {
        if (!filePathField.getText().trim().isEmpty()) {
            File file = new File(filePathField.getText());
            if (file.exists()) {
                return new String(Files.readAllBytes(file.toPath()));
            } else {
                throw new IOException("File tidak ditemukan: " + filePathField.getText());
            }
        } else {
            return inputTextArea.getText();
        }
    }
    
    private String hashWithPBKDF2(String input) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = (Integer) iterationsSpinner.getValue();
        byte[] salt = getSalt();
        
        PBEKeySpec spec = new PBEKeySpec(input.toCharArray(), salt, iterations, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = factory.generateSecret(spec).getEncoded();
        
        StringBuilder result = new StringBuilder();
        result.append("=== PBKDF2 Hash Result ===\n");
        result.append("Algoritma: PBKDF2WithHmacSHA256\n");
        result.append("Iterasi: ").append(iterations).append("\n");
        result.append("Salt Length: ").append(salt.length).append(" bytes\n");
        result.append("Salt (Base64): ").append(Base64.getEncoder().encodeToString(salt)).append("\n");
        result.append("Salt (Hex): ").append(bytesToHex(salt)).append("\n");
        result.append("Hash (Base64): ").append(Base64.getEncoder().encodeToString(hash)).append("\n");
        result.append("Hash (Hex): ").append(bytesToHex(hash));
        
        return result.toString();
    }
    
    private String hashWithBCrypt(String input) throws NoSuchAlgorithmException {
        int cost = (Integer) costSpinner.getValue();
        byte[] salt = getSalt();
        
        // Implementasi BCrypt sederhana menggunakan PBKDF2 sebagai basis
        // dengan modifikasi untuk meniru karakteristik BCrypt
        String bcryptHash = simpleBCryptHash(input, salt, cost);
        
        StringBuilder result = new StringBuilder();
        result.append("=== BCrypt-like Hash Result ===\n");
        result.append("Algoritma: BCrypt-like (Native Implementation)\n");
        result.append("Cost: ").append(cost).append(" (2^").append(cost).append(" = ").append(1 << cost).append(" rounds)\n");
        result.append("Salt Length: ").append(salt.length).append(" bytes\n");
        result.append("Salt (Base64): ").append(Base64.getEncoder().encodeToString(salt)).append("\n");
        result.append("Salt (Hex): ").append(bytesToHex(salt)).append("\n");
        result.append("Hash: ").append(bcryptHash).append("\n");
        result.append("Note: Implementasi sederhana yang meniru BCrypt menggunakan PBKDF2");
        
        return result.toString();
    }
    
    private String hashWithSCrypt(String input) throws NoSuchAlgorithmException {
        int N = (Integer) iterationsSpinner.getValue();
        int r = (Integer) costSpinner.getValue();
        int p = 1;
        byte[] salt = getSalt();
        
        // Implementasi SCrypt sederhana menggunakan PBKDF2 dengan parameter yang disesuaikan
        String scryptHash = simpleSCryptHash(input, salt, N, r, p);
        
        StringBuilder result = new StringBuilder();
        result.append("=== SCrypt-like Hash Result ===\n");
        result.append("Algoritma: SCrypt-like (Native Implementation)\n");
        result.append("N (CPU/Memory cost): ").append(N).append("\n");
        result.append("r (Block size): ").append(r).append("\n");
        result.append("p (Parallelization): ").append(p).append("\n");
        result.append("Salt Length: ").append(salt.length).append(" bytes\n");
        result.append("Salt (Base64): ").append(Base64.getEncoder().encodeToString(salt)).append("\n");
        result.append("Salt (Hex): ").append(bytesToHex(salt)).append("\n");
        result.append("Hash: ").append(scryptHash).append("\n");
        result.append("Note: Implementasi sederhana yang meniru SCrypt menggunakan PBKDF2");
        
        return result.toString();
    }
    
    private String simpleBCryptHash(String password, byte[] salt, int cost) throws NoSuchAlgorithmException {
        // Simulasi BCrypt menggunakan multiple rounds PBKDF2
        int rounds = 1 << cost; // 2^cost
        
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, rounds, 192); // 24 bytes = 192 bits
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            // Format mirip BCrypt: $2a$[cost]$[salt][hash]
            String saltB64 = Base64.getEncoder().encodeToString(salt).substring(0, Math.min(22, Base64.getEncoder().encodeToString(salt).length()));
            String hashB64 = Base64.getEncoder().encodeToString(hash).substring(0, Math.min(31, Base64.getEncoder().encodeToString(hash).length()));
            
            return String.format("$2a$%02d$%s%s", cost, saltB64, hashB64);
        } catch (Exception e) {
            throw new NoSuchAlgorithmException("Error creating BCrypt-like hash: " + e.getMessage());
        }
    }
    
    private String simpleSCryptHash(String password, byte[] salt, int N, int r, int p) throws NoSuchAlgorithmException {
        // Simulasi SCrypt menggunakan multiple rounds PBKDF2 dengan parameter yang disesuaikan
        int iterations = Math.max(1000, N * r * p); // Kombinasi parameter sebagai iteration count
        
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256); // 32 bytes
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = factory.generateSecret(spec).getEncoded();
            
            // Format SCrypt-like dengan parameter
            String combined = String.format("scrypt:N=%d:r=%d:p=%d:%s:%s", 
                N, r, p, 
                Base64.getEncoder().encodeToString(salt),
                Base64.getEncoder().encodeToString(hash));
            
            return combined;
        } catch (Exception e) {
            throw new NoSuchAlgorithmException("Error creating SCrypt-like hash: " + e.getMessage());
        }
    }
    
    private byte[] getSalt() {
        if (useCustomSaltCheck.isSelected() && !customSaltField.getText().trim().isEmpty()) {
            return customSaltField.getText().getBytes();
        } else {
            int saltLength = (Integer) saltLengthSpinner.getValue();
            byte[] salt = new byte[saltLength];
            new SecureRandom().nextBytes(salt);
            return salt;
        }
    }
    
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    private void clearAll() {
        inputTextArea.setText("");
        outputTextArea.setText("");
        filePathField.setText("");
        customSaltField.setText("");
        useCustomSaltCheck.setSelected(false);
        customSaltField.setEnabled(false);
        saltLengthSpinner.setEnabled(true);
        progressBar.setString("Siap");
        progressBar.setValue(0);
        algorithmCombo.setSelectedIndex(0);
        updateParameterVisibility();
    }
    
    private void copyResult() {
        if (!outputTextArea.getText().trim().isEmpty()) {
            outputTextArea.selectAll();
            outputTextArea.copy();
            JOptionPane.showMessageDialog(this, "Hasil berhasil disalin ke clipboard!", 
                "Copy Berhasil", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(this, "Tidak ada hasil untuk disalin!", 
                "Copy Gagal", JOptionPane.WARNING_MESSAGE);
        }
    }
    
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception e) {
                // Use default look and feel if system LAF is not available
            }
            
            new HashingApp().setVisible(true);
        });
    }
}