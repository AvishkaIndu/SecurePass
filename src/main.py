"""
SecurePass Password Manager - Main Entry Point
Handles initial setup, login, and application launch
"""
import sys
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QMessageBox,
                             QProgressBar, QFrame, QGraphicsOpacityEffect,
                             QGraphicsDropShadowEffect)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty
from PyQt5.QtGui import QFont, QPalette, QLinearGradient, QBrush, QColor, QPainter
from crypto_lib import CryptoManager
from db import DatabaseManager
from gui import MainWindow
from utils import PasswordStrengthChecker


class AnimatedLabel(QLabel):
    """Custom label with fade animation effects"""
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
        self._opacity = 1.0
        self.opacity_effect = QGraphicsOpacityEffect()
        self.setGraphicsEffect(self.opacity_effect)
        
    def get_opacity(self):
        return self._opacity
        
    def set_opacity(self, value):
        self._opacity = value
        self.opacity_effect.setOpacity(value)
        
    opacity = pyqtProperty(float, get_opacity, set_opacity)
    
    def fade_in(self, duration=500):
        """Animate fade in effect"""
        self.animation = QPropertyAnimation(self, b"opacity")
        self.animation.setDuration(duration)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.OutCubic)
        self.animation.start()


class SecurityFrame(QFrame):
    """Custom frame with security-themed styling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.NoFrame)
        
        # Add drop shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(25)
        shadow.setXOffset(0)
        shadow.setYOffset(5)
        shadow.setColor(QColor(0, 0, 0, 80))
        self.setGraphicsEffect(shadow)


class LoginWindow(QDialog):
    """Login/Setup window for master password"""

    def __init__(self):
        super().__init__()
        self.crypto = CryptoManager()
        self.db = DatabaseManager()
        self.setup_mode = self.db.get_config('salt') is None
        self.setup_ui()

    def setup_ui(self):
        """Initialize login UI with cybersecurity theme"""
        self.setWindowTitle("CyberVault - Secure Access Terminal")
        self.setFixedSize(500, 650)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowTitleHint)

        # Apply cybersecurity-themed dark theme
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0a0a0a, stop:0.3 #1a1a2e, stop:0.7 #16213e, stop:1 #0a0a0a);
                color: #00ff00;
                font-family: 'Consolas', 'Courier New', monospace;
                border: 3px solid #00ff41;
                border-radius: 0px;
            }
            QLabel {
                color: #00ff00;
                font-size: 12pt;
                background: transparent;
                border: none;
            }
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #001100, stop:1 #002200);
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 12px 15px;
                color: #00ff00;
                font-size: 12pt;
                font-family: 'Consolas', monospace;
                selection-background-color: #00ff41;
                selection-color: #000000;
            }
            QLineEdit:focus {
                border: 2px solid #00ff88;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #002200, stop:1 #001a00);
                box-shadow: 0 0 20px rgba(0, 255, 65, 0.5);
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #003300, stop:0.5 #00ff41, stop:1 #003300);
                color: #000000;
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 12pt;
                font-family: 'Consolas', monospace;
                min-height: 20px;
                text-transform: uppercase;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ff41, stop:0.5 #66ff88, stop:1 #00ff41);
                box-shadow: 0 0 15px rgba(0, 255, 65, 0.7);
                color: #000000;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #002200, stop:0.5 #00aa22, stop:1 #002200);
                color: #00ff00;
            }
            QProgressBar {
                border: 2px solid #00ff41;
                border-radius: 0px;
                text-align: center;
                background: #001100;
                height: 25px;
                color: #00ff00;
                font-weight: bold;
                font-family: 'Consolas', monospace;
            }
            QProgressBar::chunk {
                border-radius: 0px;
                margin: 1px;
            }
            QFrame#cyber_frame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(0, 255, 65, 0.1), 
                    stop:0.5 rgba(0, 255, 65, 0.05), 
                    stop:1 rgba(0, 255, 65, 0.1));
                border: 2px solid #00ff41;
                border-radius: 0px;
                padding: 20px;
            }
        """)

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)

        # Cyber frame container
        cyber_frame = SecurityFrame()
        cyber_frame.setObjectName("cyber_frame")
        frame_layout = QVBoxLayout(cyber_frame)
        frame_layout.setSpacing(20)
        frame_layout.setContentsMargins(20, 20, 20, 20)

        # ASCII Art Header
        ascii_header = QLabel("""
 ▄████▄▓██   ██▓ ▄▄▄▄   ▓█████  ██▀███  
▒██▀ ▀█ ▒██  ██▒▓█████▄ ▓█   ▀ ▓██   ▒ 
▒▓█    ▄ ▒██ ██░▒██▒ ▄██▒███   ▓██▄   
▒▓▓▄ ▄██▒░ ▐██▓░▒██░█▀  ▒▓█  ▄ ▒   ██▒
▒ ▓███▀ ░░ ██▒▓░░▓█  ▀█▓░▒████▒░██████▒
░ ░▒ ▒  ░ ██▒▒▒ ░▒▓███▀▒░░ ▒░ ░░ ▒░▓  ░
        """)
        ascii_header.setAlignment(Qt.AlignCenter)
        ascii_header.setStyleSheet("""
            color: #00ff41;
            font-family: 'Consolas', monospace;
            font-size: 9pt;
            font-weight: bold;
            padding: 10px;
            background: rgba(0, 0, 0, 0.5);
            border: 1px solid #00ff41;
        """)
        frame_layout.addWidget(ascii_header)

        # System Status
        status_text = "[SYSTEM] INITIALIZING SECURE CONNECTION..."
        if not self.setup_mode:
            status_text = "[SYSTEM] AWAITING AUTHENTICATION..."
        
        self.system_status = AnimatedLabel(status_text)
        self.system_status.setAlignment(Qt.AlignCenter)
        self.system_status.setStyleSheet("""
            color: #00ff88;
            font-family: 'Consolas', monospace;
            font-size: 11pt;
            font-weight: bold;
            padding: 10px;
            background: rgba(0, 255, 65, 0.1);
            border: 1px solid #00ff41;
            border-radius: 0px;
        """)
        frame_layout.addWidget(self.system_status)

        # Terminal-style instruction
        instruction_text = "[VAULT] CREATE MASTER ACCESS CODE" if self.setup_mode else "[AUTH] ENTER ACCESS CREDENTIALS"
        instruction = QLabel(instruction_text)
        instruction.setAlignment(Qt.AlignCenter)
        instruction.setStyleSheet("""
            color: #00ddff;
            font-family: 'Consolas', monospace;
            font-size: 10pt;
            padding: 8px;
            background: rgba(0, 221, 255, 0.1);
            border: 1px dashed #00ddff;
        """)
        frame_layout.addWidget(instruction)

        # Password input section
        input_section = QVBoxLayout()
        input_section.setSpacing(15)

        # Master password input
        pwd_label = QLabel("[INPUT] MASTER_PASSWORD:")
        pwd_label.setStyleSheet("font-weight: bold; font-size: 11pt; color: #00ff88;")
        input_section.addWidget(pwd_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter secure access code...")
        self.password_input.returnPressed.connect(self.handle_login)
        input_section.addWidget(self.password_input)

        if self.setup_mode:
            # Confirm password
            confirm_label = QLabel("[VERIFY] CONFIRM_PASSWORD:")
            confirm_label.setStyleSheet("font-weight: bold; font-size: 11pt; color: #00ff88;")
            input_section.addWidget(confirm_label)
            
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Re-enter access code...")
            self.confirm_input.returnPressed.connect(self.handle_login)
            input_section.addWidget(self.confirm_input)

            # Password strength with cyber styling
            self.password_input.textChanged.connect(self.update_strength)
            
            strength_label = QLabel("[ANALYSIS] PASSWORD_STRENGTH:")
            strength_label.setStyleSheet("font-weight: bold; font-size: 10pt; color: #ffaa00;")
            input_section.addWidget(strength_label)
            
            self.strength_bar = QProgressBar()
            self.strength_bar.setMaximum(100)
            input_section.addWidget(self.strength_bar)
            
            self.strength_label = QLabel("[STATUS] ANALYZING...")
            self.strength_label.setStyleSheet("font-size: 9pt; color: #00ff88; font-family: 'Consolas', monospace;")
            self.strength_label.setAlignment(Qt.AlignCenter)
            input_section.addWidget(self.strength_label)

            # Cyber security warning
            warning = QLabel("[WARNING] CRITICAL_SECURITY_NOTICE")
            warning.setAlignment(Qt.AlignCenter)
            warning.setStyleSheet("""
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(255, 0, 0, 0.2), 
                    stop:1 rgba(255, 100, 0, 0.2));
                border: 2px solid #ff3300;
                border-radius: 0px;
                padding: 12px;
                color: #ff6600;
                font-size: 10pt;
                font-weight: bold;
                font-family: 'Consolas', monospace;
                margin: 10px 0;
            """)
            input_section.addWidget(warning)
            
            warning_detail = QLabel("[INFO] ACCESS CODE CANNOT BE RECOVERED IF LOST\n[ACTION] STORE IN SECURE LOCATION")
            warning_detail.setAlignment(Qt.AlignCenter)
            warning_detail.setStyleSheet("""
                color: #ff8800; 
                font-size: 9pt; 
                font-family: 'Consolas', monospace;
                padding: 5px;
                background: rgba(255, 136, 0, 0.1);
                border: 1px dashed #ff8800;
            """)
            input_section.addWidget(warning_detail)

        frame_layout.addLayout(input_section)

        # Action button
        btn_text = "[INITIALIZE] CREATE_VAULT" if self.setup_mode else "[EXECUTE] ACCESS_VAULT"
        self.login_btn = QPushButton(btn_text)
        self.login_btn.clicked.connect(self.handle_login)
        self.login_btn.setMinimumHeight(50)
        frame_layout.addWidget(self.login_btn)

        # System info
        info_text = "[CRYPTO] INITIALIZING AES-256 ENCRYPTION" if self.setup_mode else "[SYSTEM] DECRYPTION_MODULE_READY"
        self.info_label = AnimatedLabel(info_text)
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("""
            background: rgba(0, 100, 255, 0.1);
            border: 1px solid #0066ff;
            border-radius: 0px;
            padding: 10px;
            color: #0088ff;
            font-size: 9pt;
            font-family: 'Consolas', monospace;
        """)
        frame_layout.addWidget(self.info_label)

        main_layout.addWidget(cyber_frame)
        
        # Start entrance animations
        QTimer.singleShot(100, self.animate_entrance)

        # Apply modern security-themed dark theme
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0f1419, stop:0.5 #1a1f2e, stop:1 #0f1419);
                color: #e0e6ed;
                font-family: 'Segoe UI', 'San Francisco', Arial;
                border: 2px solid #2d3748;
                border-radius: 15px;
            }
            QLabel {
                color: #e0e6ed;
                font-size: 12pt;
                background: transparent;
            }
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 10px;
                padding: 15px 20px;
                color: #e0e6ed;
                font-size: 12pt;
                selection-background-color: #0d7377;
            }
            QLineEdit:focus {
                border: 2px solid #0d7377;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0d7377, stop:0.1 #2d3748, stop:1 #1a202c);
                box-shadow: 0 0 20px rgba(13, 115, 119, 0.3);
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0d7377, stop:0.5 #14a085, stop:1 #0d7377);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 15px 25px;
                font-weight: bold;
                font-size: 13pt;
                min-height: 20px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #14a085, stop:0.5 #17c4a5, stop:1 #14a085);
                transform: translateY(-2px);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0a5f63, stop:0.5 #0d7377, stop:1 #0a5f63);
                transform: translateY(1px);
            }
            QProgressBar {
                border: 2px solid #4a5568;
                border-radius: 8px;
                text-align: center;
                background: #1a202c;
                height: 25px;
                color: white;
                font-weight: bold;
            }
            QProgressBar::chunk {
                border-radius: 6px;
                margin: 1px;
            }
            QFrame#security_frame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(45, 55, 72, 0.8), 
                    stop:0.5 rgba(26, 32, 44, 0.9), 
                    stop:1 rgba(45, 55, 72, 0.8));
                border: 1px solid #4a5568;
                border-radius: 15px;
                padding: 20px;
            }
        """)

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(25)
        main_layout.setContentsMargins(40, 40, 40, 40)

        # Security frame container
        security_frame = SecurityFrame()
        security_frame.setObjectName("security_frame")
        frame_layout = QVBoxLayout(security_frame)
        frame_layout.setSpacing(20)
        frame_layout.setContentsMargins(30, 30, 30, 30)

        # Animated title with security icon
        title_container = QVBoxLayout()
        title_container.setSpacing(10)
        
        self.title = AnimatedLabel("�️ SecurePass")
        self.title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Segoe UI", 24, QFont.Bold)
        self.title.setFont(title_font)
        self.title.setStyleSheet("""
            color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #0d7377, stop:0.5 #14a085, stop:1 #0d7377);
            padding: 10px;
        """)
        title_container.addWidget(self.title)
        
        # Animated subtitle
        self.subtitle = AnimatedLabel("Professional Password Management" if not self.setup_mode else "Vault Initialization")
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setStyleSheet("""
            color: #a0aec0; 
            font-size: 11pt; 
            font-weight: 300;
            padding: 5px;
        """)
        title_container.addWidget(self.subtitle)
        
        frame_layout.addLayout(title_container)
        frame_layout.addSpacing(15)

        # Security status indicator
        self.security_status = AnimatedLabel("🔒 Encrypted • 🔐 Secure • 🛡️ Protected")
        self.security_status.setAlignment(Qt.AlignCenter)
        self.security_status.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(13, 115, 119, 0.2), 
                stop:0.5 rgba(20, 160, 133, 0.3), 
                stop:1 rgba(13, 115, 119, 0.2));
            border: 1px solid #0d7377;
            border-radius: 20px;
            padding: 10px;
            font-size: 10pt;
            color: #81e6d9;
        """)
        frame_layout.addWidget(self.security_status)
        frame_layout.addSpacing(10)

        # Password input section
        input_section = QVBoxLayout()
        input_section.setSpacing(15)

        # Master password label
        password_label = QLabel("🔑 Master Password")
        password_label.setStyleSheet("font-weight: bold; font-size: 11pt; color: #e0e6ed;")
        input_section.addWidget(password_label)

        # Password input with icon
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your secure master password...")
        self.password_input.returnPressed.connect(self.handle_login)
        input_section.addWidget(self.password_input)

        if self.setup_mode:
            # Confirm password for setup
            confirm_label = QLabel("🔒 Confirm Password")
            confirm_label.setStyleSheet("font-weight: bold; font-size: 11pt; color: #e0e6ed;")
            input_section.addWidget(confirm_label)
            
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Re-enter password to confirm...")
            self.confirm_input.returnPressed.connect(self.handle_login)
            input_section.addWidget(self.confirm_input)

            # Password strength indicator with enhanced styling
            self.password_input.textChanged.connect(self.update_strength)
            
            strength_label = QLabel("🎯 Password Strength")
            strength_label.setStyleSheet("font-weight: bold; font-size: 10pt; color: #a0aec0;")
            input_section.addWidget(strength_label)
            
            self.strength_bar = QProgressBar()
            self.strength_bar.setMaximum(100)
            input_section.addWidget(self.strength_bar)
            
            self.strength_label = QLabel("Enter password to check strength")
            self.strength_label.setStyleSheet("font-size: 9pt; color: #718096; text-align: center;")
            self.strength_label.setAlignment(Qt.AlignCenter)
            input_section.addWidget(self.strength_label)

            # Security warning with enhanced styling
            warning = QLabel("⚠️ CRITICAL SECURITY NOTICE")
            warning.setAlignment(Qt.AlignCenter)
            warning.setStyleSheet("""
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 rgba(245, 101, 101, 0.2), 
                    stop:1 rgba(246, 173, 85, 0.2));
                border: 1px solid #f56565;
                border-radius: 8px;
                padding: 15px;
                color: #feb2b2;
                font-size: 10pt;
                font-weight: bold;
                margin: 10px 0;
            """)
            input_section.addWidget(warning)
            
            warning_detail = QLabel("Your master password cannot be recovered if lost.\nStore it in a secure location.")
            warning_detail.setAlignment(Qt.AlignCenter)
            warning_detail.setStyleSheet("color: #fbb6ce; font-size: 9pt; padding: 5px;")
            input_section.addWidget(warning_detail)

        frame_layout.addLayout(input_section)
        frame_layout.addSpacing(15)

        # Action button
        btn_text = "🛡️ Create Secure Vault" if self.setup_mode else "🔓 Unlock Vault"
        self.login_btn = QPushButton(btn_text)
        self.login_btn.clicked.connect(self.handle_login)
        self.login_btn.setMinimumHeight(50)
        frame_layout.addWidget(self.login_btn)

        # Info section
        info_text = (
            "🔐 Initializing encrypted vault with AES-256 encryption"
            if self.setup_mode
            else "🔑 Enter master password to decrypt your secure vault"
        )
        self.info_label = AnimatedLabel(info_text)
        self.info_label.setAlignment(Qt.AlignCenter)
        self.info_label.setStyleSheet("""
            background: rgba(74, 85, 104, 0.3);
            border: 1px solid #4a5568;
            border-radius: 8px;
            padding: 12px;
            color: #a0aec0;
            font-size: 9pt;
        """)
        frame_layout.addWidget(self.info_label)

        main_layout.addWidget(security_frame)
        
        # Start entrance animations
        QTimer.singleShot(100, self.animate_entrance)

    def animate_entrance(self):
        """Animate the entrance of UI elements"""
        self.title.fade_in(800)
        QTimer.singleShot(200, lambda: self.subtitle.fade_in(600))
        QTimer.singleShot(400, lambda: self.security_status.fade_in(500))
        QTimer.singleShot(600, lambda: self.info_label.fade_in(400))

    def update_strength(self):
        """Update password strength indicator with cyber styling"""
        if not self.setup_mode:
            return

        password = self.password_input.text()
        score, label, color = PasswordStrengthChecker.check_strength(password)
        
        # Cyber-themed strength bar styling
        self.strength_bar.setValue(score)
        
        # Cyber status messages
        if score < 25:
            cyber_label = "[THREAT] WEAK_SECURITY"
            gradient_color = "#ff0040"
            text_color = "#ff4080"
        elif score < 50:
            cyber_label = "[CAUTION] MODERATE_SECURITY"
            gradient_color = "#ff8000"
            text_color = "#ffaa40"
        elif score < 75:
            cyber_label = "[GOOD] STRONG_SECURITY"
            gradient_color = "#ffff00"
            text_color = "#ffff80"
        else:
            cyber_label = "[SECURE] MAXIMUM_SECURITY"
            gradient_color = "#00ff40"
            text_color = "#80ff80"
            
        self.strength_label.setText(cyber_label)
        
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {gradient_color}, stop:1 rgba(0,255,65,0.3));
                border-radius: 0px;
                margin: 1px;
            }}
        """)
        self.strength_label.setStyleSheet(f"font-size: 9pt; color: {text_color}; font-weight: bold; font-family: 'Consolas', monospace;")

    def handle_login(self):
        """Handle login or initial setup"""
        password = self.password_input.text()

        if not password:
            QMessageBox.warning(self, "Error", "Please enter a password")
            return

        if self.setup_mode:
            # Initial setup
            confirm = self.confirm_input.text()
            if password != confirm:
                QMessageBox.warning(self, "Error", "Passwords do not match")
                return

            # Check password strength
            score, _, _ = PasswordStrengthChecker.check_strength(password)
            if score < 50:
                reply = QMessageBox.question(
                    self, "Weak Password",
                    "Your password is weak. Continue anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            try:
                # Generate salt and derive key
                self.crypto.derive_key(password)

                # Store salt and iterations
                self.db.save_config('salt', self.crypto.get_salt_b64())
                self.db.save_config('iterations', str(CryptoManager.ITERATIONS))

                QMessageBox.information(
                    self, "Success",
                    "Vault created successfully!\n\nYou can now add your credentials."
                )

                self.launch_main_window()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Setup failed: {str(e)}")
        else:
            # Login with existing vault
            try:
                # Load salt
                salt_b64 = self.db.get_config('salt')
                self.crypto.set_salt_from_b64(salt_b64)

                # Derive key from password
                self.crypto.derive_key(password, self.crypto.salt)

                # Verify by attempting to decrypt a credential (if any exist)
                credentials = self.db.get_all_credentials()
                if credentials:
                    # Try to decrypt first credential as verification
                    try:
                        self.crypto.decrypt(credentials[0]['password_encrypted'])
                    except:
                        QMessageBox.critical(self, "Error", "Invalid master password")
                        return

                self.launch_main_window()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")

    def launch_main_window(self):
        """Launch main application window"""
        self.main_window = MainWindow(self.crypto, self.db)
        self.main_window.show()
        self.accept()


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern look

    # Set application metadata
    app.setApplicationName("SecurePass")
    app.setOrganizationName("SecurePass")

    # Show login window
    login = LoginWindow()
    login.show()

    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
