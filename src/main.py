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
        """Initialize cybersecurity-themed login UI"""
        self.setWindowTitle("⚡ SECUREPASS - CYBER DEFENSE SYSTEM ⚡")
        self.setFixedSize(550, 650)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowTitleHint)

        # Apply cybersecurity dark theme with neon effects
        self.setStyleSheet("""
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #000814, stop:0.3 #001d3d, stop:0.7 #003566, stop:1 #000814);
                color: #00f5ff;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                border: 3px solid #00f5ff;
                border-radius: 8px;
                background-image: 
                    radial-gradient(circle at 20% 50%, rgba(0, 245, 255, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 80% 20%, rgba(57, 255, 20, 0.1) 0%, transparent 50%),
                    radial-gradient(circle at 40% 80%, rgba(255, 20, 147, 0.1) 0%, transparent 50%);
            }
            QLabel {
                color: #00f5ff;
                font-size: 12pt;
                background: transparent;
                font-weight: bold;
                text-shadow: 0 0 10px #00f5ff;
            }
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(0, 0, 0, 0.8), stop:1 rgba(0, 20, 40, 0.8));
                border: 2px solid #39ff14;
                border-radius: 6px;
                padding: 12px 16px;
                color: #00f5ff;
                font-size: 11pt;
                font-family: 'Consolas', monospace;
                selection-background-color: #39ff14;
                font-weight: bold;
            }
            QLineEdit:focus {
                border: 2px solid #00f5ff;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(0, 245, 255, 0.1), stop:1 rgba(0, 20, 40, 0.9));
                box-shadow: 0 0 20px rgba(0, 245, 255, 0.6);
            }
            QLineEdit::placeholder {
                color: #39ff14;
                font-style: italic;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(57, 255, 20, 0.8), 
                    stop:0.5 rgba(0, 245, 255, 0.8), 
                    stop:1 rgba(57, 255, 20, 0.8));
                color: #000814;
                border: 2px solid #39ff14;
                border-radius: 8px;
                padding: 12px 20px;
                font-weight: bold;
                font-size: 11pt;
                font-family: 'Consolas', monospace;
                min-height: 20px;
                text-transform: uppercase;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(0, 245, 255, 0.9), 
                    stop:0.5 rgba(57, 255, 20, 0.9), 
                    stop:1 rgba(0, 245, 255, 0.9));
                box-shadow: 0 0 25px rgba(57, 255, 20, 0.8);
                transform: translateY(-2px);
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 rgba(255, 20, 147, 0.8), 
                    stop:1 rgba(57, 255, 20, 0.8));
                transform: translateY(1px);
                box-shadow: 0 0 15px rgba(255, 20, 147, 0.6);
            }
            QProgressBar {
                border: 2px solid #39ff14;
                border-radius: 6px;
                text-align: center;
                background: rgba(0, 0, 0, 0.8);
                height: 20px;
                color: #00f5ff;
                font-weight: bold;
                font-family: 'Consolas', monospace;
            }
            QProgressBar::chunk {
                border-radius: 4px;
                margin: 1px;
            }
            QFrame#security_frame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 rgba(0, 245, 255, 0.1), 
                    stop:0.5 rgba(57, 255, 20, 0.1), 
                    stop:1 rgba(0, 245, 255, 0.1));
                border: 2px solid #00f5ff;
                border-radius: 10px;
                padding: 15px;
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
        
        self.title = AnimatedLabel("⚡ SECUREPASS ⚡")
        self.title.setAlignment(Qt.AlignCenter)
        title_font = QFont("Consolas", 28, QFont.Bold)
        self.title.setFont(title_font)
        self.title.setStyleSheet("""
            color: #00f5ff;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(0, 245, 255, 0.2), 
                stop:0.5 rgba(57, 255, 20, 0.2), 
                stop:1 rgba(0, 245, 255, 0.2));
            border: 2px solid #39ff14;
            border-radius: 8px;
            padding: 8px;
            text-shadow: 0 0 15px #00f5ff;
        """)
        title_container.addWidget(self.title)
        
        # Cyber subtitle with matrix effect
        self.subtitle = AnimatedLabel("[CYBER DEFENSE PROTOCOL]" if not self.setup_mode else "[INITIALIZING SECURE VAULT]")
        self.subtitle.setAlignment(Qt.AlignCenter)
        self.subtitle.setStyleSheet("""
            color: #39ff14; 
            font-size: 10pt; 
            font-weight: bold;
            font-family: 'Consolas', monospace;
            padding: 5px;
            text-shadow: 0 0 8px #39ff14;
            background: rgba(57, 255, 20, 0.1);
            border: 1px solid #39ff14;
            border-radius: 4px;
        """)
        title_container.addWidget(self.subtitle)
        
        frame_layout.addLayout(title_container)
        frame_layout.addSpacing(15)

        # Cyber security status indicator
        self.security_status = AnimatedLabel("⚡ ENCRYPTED ⚡ • 🔐 SECURE • ⛨ PROTECTED ⛨")
        self.security_status.setAlignment(Qt.AlignCenter)
        self.security_status.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 rgba(0, 245, 255, 0.2), 
                stop:0.5 rgba(57, 255, 20, 0.3), 
                stop:1 rgba(0, 245, 255, 0.2));
            border: 2px solid #00f5ff;
            border-radius: 15px;
            padding: 8px;
            font-size: 9pt;
            color: #00f5ff;
            font-family: 'Consolas', monospace;
            font-weight: bold;
            text-shadow: 0 0 10px #00f5ff;
        """)
        frame_layout.addWidget(self.security_status)
        frame_layout.addSpacing(10)

        # Password input section
        input_section = QVBoxLayout()
        input_section.setSpacing(15)

        # Master password label with cyber styling
        password_label = QLabel("⚡ MASTER ACCESS KEY ⚡")
        password_label.setStyleSheet("""
            font-weight: bold; 
            font-size: 11pt; 
            color: #00f5ff;
            font-family: 'Consolas', monospace;
            text-shadow: 0 0 8px #00f5ff;
        """)
        input_section.addWidget(password_label)

        # Password input with cyber styling
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText(">>> ENTER SECURE ACCESS CREDENTIALS <<<")
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
        
        # Cyber-enhanced strength bar styling
        self.strength_bar.setValue(score)
        self.strength_label.setText(f"⚡ SECURITY LEVEL: {label.upper()} ⚡")
        
        # Cyber color scheme based on strength
        if score < 25:
            gradient_color = "#ff1744"  # Cyber Red
            text_color = "#ff5722"
            glow_color = "#ff1744"
        elif score < 50:
            gradient_color = "#ff9800"  # Cyber Orange
            text_color = "#ffb74d"
            glow_color = "#ff9800"
        elif score < 75:
            gradient_color = "#ffeb3b"  # Cyber Yellow
            text_color = "#fff176"
            glow_color = "#ffeb3b"
        else:
            gradient_color = "#39ff14"  # Cyber Green
            text_color = "#76ff03"
            glow_color = "#39ff14"
            
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {gradient_color}, 
                    stop:0.5 rgba(0, 245, 255, 0.5), 
                    stop:1 {gradient_color});
                border-radius: 4px;
                margin: 1px;
                box-shadow: 0 0 15px {glow_color};
            }}
        """)
        self.strength_label.setStyleSheet(f"""
            font-size: 9pt; 
            color: {text_color}; 
            font-weight: bold;
            font-family: 'Consolas', monospace;
            text-shadow: 0 0 8px {glow_color};
        """)

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
