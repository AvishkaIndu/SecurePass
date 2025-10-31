import sys
from PyQt5.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QMessageBox,
                             QProgressBar, QFrame, QGraphicsOpacityEffect,
                             QGraphicsDropShadowEffect)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtProperty, QRect
from PyQt5.QtGui import QFont, QPalette, QLinearGradient, QBrush, QColor, QPainter, QPen
from crypto_lib import CryptoManager
from db import DatabaseManager
from gui import MainWindow
from utils import PasswordStrengthChecker


class CyberSecurityFrame(QFrame):
    """Enhanced security frame with cyber animations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.NoFrame)
        self.grid_alpha = 0.0
        self.scan_position = 0
        
        # Add animated shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(30)
        shadow.setXOffset(0)
        shadow.setYOffset(8)
        shadow.setColor(QColor(13, 115, 119, 120))
        self.setGraphicsEffect(shadow)
        
        # Start cyber animations
        self.start_cyber_animations()
    
    def start_cyber_animations(self):
        """Start cybersecurity-themed animations"""
        # Grid animation
        self.grid_timer = QTimer()
        self.grid_timer.timeout.connect(self.animate_grid)
        self.grid_timer.start(100)
        
        # Scanning animation
        self.scan_timer = QTimer()
        self.scan_timer.timeout.connect(self.animate_scan)
        self.scan_timer.start(50)
    
    def animate_grid(self):
        """Animate background grid effect"""
        self.grid_alpha = (self.grid_alpha + 0.02) % 1.0
        self.update()
    
    def animate_scan(self):
        """Animate scanning line effect"""
        self.scan_position = (self.scan_position + 2) % self.width()
        self.update()
    
    def paintEvent(self, event):
        """Custom paint event for cyber effects"""
        super().paintEvent(event)
        
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw cyber grid pattern
        grid_color = QColor(13, 115, 119, int(50 + 30 * self.grid_alpha))
        painter.setPen(QPen(grid_color, 1))
        
        # Draw grid lines
        for x in range(0, self.width(), 30):
            painter.drawLine(x, 0, x, self.height())
        for y in range(0, self.height(), 30):
            painter.drawLine(0, y, self.width(), y)
        
        # Draw scanning line
        scan_color = QColor(20, 160, 133, 150)
        painter.setPen(QPen(scan_color, 2))
        painter.drawLine(self.scan_position, 0, self.scan_position, self.height())
        
        # Draw corner brackets (cyber style)
        bracket_color = QColor(13, 115, 119, 200)
        painter.setPen(QPen(bracket_color, 3))
        
        # Top-left bracket
        painter.drawLine(10, 10, 30, 10)
        painter.drawLine(10, 10, 10, 30)
        
        # Top-right bracket
        painter.drawLine(self.width() - 30, 10, self.width() - 10, 10)
        painter.drawLine(self.width() - 10, 10, self.width() - 10, 30)
        
        # Bottom-left bracket
        painter.drawLine(10, self.height() - 30, 10, self.height() - 10)
        painter.drawLine(10, self.height() - 10, 30, self.height() - 10)
        
        # Bottom-right bracket
        painter.drawLine(self.width() - 10, self.height() - 30, self.width() - 10, self.height() - 10)
        painter.drawLine(self.width() - 30, self.height() - 10, self.width() - 10, self.height() - 10)


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


class SecurityFrame(CyberSecurityFrame):
    """Custom frame with enhanced cybersecurity styling and animations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        # Additional security frame specific styling will be handled by CSS


class LoginWindow(QDialog):
    """Login/Setup window for master password"""

    def __init__(self):
        super().__init__()
        self.crypto = CryptoManager()
        self.db = DatabaseManager()
        self.setup_mode = self.db.get_config('salt') is None
        self.setup_ui()

    def setup_ui(self):
        """Initialize login UI with modern security-focused design"""
        self.setWindowTitle("SecurePass - Secure Authentication")
        self.setFixedSize(520, 650)
        self.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowTitleHint)

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
                padding: 5px;
                min-height: 25px;
            }
            QLineEdit {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2d3748, stop:1 #1a202c);
                border: 2px solid #4a5568;
                border-radius: 10px;
                padding: 18px 22px;
                color: #e0e6ed;
                font-size: 13pt;
                min-height: 20px;
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
                padding: 18px 28px;
                font-weight: bold;
                font-size: 14pt;
                min-height: 25px;
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
        """Update password strength indicator with enhanced styling"""
        if not self.setup_mode:
            return

        password = self.password_input.text()
        score, label, color = PasswordStrengthChecker.check_strength(password)
        
        # Enhanced strength bar styling
        self.strength_bar.setValue(score)
        self.strength_label.setText(f"🎯 Strength: {label}")
        
        # Color gradient based on strength
        if score < 25:
            gradient_color = "#f56565"  # Red
            text_color = "#feb2b2"
        elif score < 50:
            gradient_color = "#ed8936"  # Orange
            text_color = "#fbd38d"
        elif score < 75:
            gradient_color = "#ecc94b"  # Yellow
            text_color = "#f6e05e"
        else:
            gradient_color = "#48bb78"  # Green
            text_color = "#9ae6b4"
            
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {gradient_color}, stop:1 rgba(255,255,255,0.3));
                border-radius: 6px;
                margin: 1px;
            }}
        """)
        self.strength_label.setStyleSheet(f"font-size: 9pt; color: {text_color}; font-weight: bold;")

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
